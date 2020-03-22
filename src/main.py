import os
import sys
import argparse

import numpy as np
import tables
import binascii


def key2mat(key):
    # change 128 bit string key into a 4*4 matrix
    tmpList = []
    for i in range(0, len(key),2):
        tmp = '0x' + key[i:i+2]
        tmpList.append(tmp)
    mapping = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
    rtn, tmp = [], []
    for i in range(len(tmpList)):
        item = int(tmpList[mapping[i]], 16)
        if i%4==0 and i!=0:
            rtn.append(tmp)
            tmp = []
        tmp.append(item)
    rtn.append(tmp)
    keyMat = np.array(rtn)
    return keyMat


def loadKey(fpath):
    with open(fpath, 'r') as f:
        lines = f.readlines()
    key1 = lines[0].strip()
    key2 = lines[1].strip()
    key1 = key2mat(key1)
    key2 = key2mat(key2)
    return key1, key2


def loadMsg(fpath):
    # load msg and change them into ASCII
    with open(fpath, 'r') as f:
        msg = f.read()
    msg = msg.strip()
    return msg


def XOR(inp1, inp2):
    tmpList = []
    for i in range(len(inp1)):
        tmp = inp1[i] ^ inp2[i]
        tmpList.append(tmp)
    return tmpList


def list2str(input_list):
    # input list here is a list of decimal number
    output = []
    for item in input_list:
        tmp = hex(item)[2:]
        if len(tmp) < 2:
            tmp = '0' + tmp
        output.append(tmp)
    return ''.join(output)


class AES():
    def __init__(self):
        pass

    def initialState(self, msg_str):
        """
        4 by 4 array of bytes with message, equals to 4*4*8=128
        Describe a block as a matrix, use it as initial State
        In this matrix, we use int value to represent hex value of each one
        """
        def byte2matrix(text):
            # converts a 16-byte array into a 4*4 matrix
            rtn, tmpList = [], []
            for i in range(0, len(text),2):
                tmp = text[i:i+2]
                tmp = '0x' + tmp.decode('utf-8')
                tmpList.append(tmp)
            mapping = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
            tmp = []
            for i in range(len(mapping)):
                item = int(tmpList[mapping[i]], 16)
                if i%4==0 and i!=0:
                    rtn.append(tmp)
                    tmp = []
                tmp.append(item)
            rtn.append(tmp)
            return np.array(rtn)

        msg_byte = binascii.b2a_hex(msg_str.encode('utf-8'))
        msg_mat = byte2matrix(msg_byte)    # it is not real matrix, it is a 2D list
        return msg_mat

    def addKey(self, msgMatrix, keyMatrix):
        # a 128-bit subkey XOR with State
        assert(msgMatrix.shape == keyMatrix.shape)
        rtnMatrix = np.zeros(msgMatrix.shape, dtype=np.int)
        for i in range(msgMatrix.shape[0]):
            for j in range(msgMatrix.shape[1]):
                rtnMatrix[i][j] = msgMatrix[i][j] ^ keyMatrix[i][j]
        return rtnMatrix

    def subBytes(self, input):
        """
        substitute each byte in State
        A 16*16 lookup table to find a replacement byte for a given byte
        """
        sbox = tables.getSbox()
        output = np.zeros(input.shape, dtype=np.int)
        for i in range(input.shape[0]):
            for j in range(input.shape[1]):
                index_value = input[i,j]
                new_value = sbox[index_value]
                output[i,j] = new_value
        return output

    def shiftRows(self, input):
        # shift bytes in State
        rtn = []
        def shiftOneRow(row, num):
            row = list(row)
            first_part = row[num:]
            latter_part = row[0:num]
            first_part.extend(latter_part)
            return first_part
        rtn.append(input[0])
        for i in range(input.shape[0]-1):
            row = input[i+1, :]
            new_row = shiftOneRow(row, i+1)
            rtn.append(new_row)
        return np.array(rtn)

    def mixSingleColumns(self, fixed_mat, col):
        rtn = []
        def multiOneRow(row1, row2):
            row1, row2 = list(row1), list(row2)
            assert(len(row1) == len(row2))
            tmpList = []
            for i in range(len(row1)):
                if 3 == row1[i]:
                    tmp = ((row2[i]<<1)%256)^row2[i]
                    if row2[i] >= 128:
                        tmp = tmp^0b00011011
                elif 2 == row1[i]:
                    tmp = (row2[i]<<1)%256
                    if row2[i] >= 128:
                        tmp = tmp^0b00011011
                else:
                    tmp = row2[i]

                tmpList.append(tmp)
            rtn = tmpList[0]
            for i in range(len(tmpList)-1):
                rtn = rtn ^ tmpList[i+1]
            return rtn
        for i in range(4):
            tmp_row = fixed_mat[i]
            tmp = multiOneRow(tmp_row, col)
            rtn.append(tmp)
        return rtn

    def mixColumns(self, input_mat):
        """
        invertible transformation on each column; skip this
        step in the final round
        """
        fixed_mat = np.array([[2,3,1,1],
                              [1,2,3,1],
                              [1,1,2,3],
                              [3,1,1,2]])
        inv_mat = input_mat.T
        rtn = []
        for i in range(4):
            col = inv_mat[i]
            new_col = self.mixSingleColumns(fixed_mat, col)
            rtn.append(new_col)
        new_rtn = np.array(rtn)
        new_rtn = new_rtn.T
        return new_rtn


    def oneRound(self, input_mat, subkey1):
        state_mat = input_mat
        # for each round
        state_mat = self.subBytes(state_mat)

        state_mat = self.shiftRows(state_mat)

        state_mat = self.mixColumns(state_mat)

        state_mat = self.addKey(state_mat, subkey1)

        return state_mat

    def toHex(self, msg_mat):
        new_mat = msg_mat.T
        tmp_list = []
        for i in range(4):
            tmp = list(new_mat[i])
            tmp_list.extend(tmp)
        rtn = '0x'
        for item in tmp_list:
            tmp = hex(item)[2:]
            if len(tmp)<2:
                tmp = '0' + tmp
            rtn = rtn + tmp
        return rtn

    def encrypt(self, opts):
        subkey1, subkey2 = loadKey(opts.keyPath)
        msg = loadMsg(opts.msgPath)
        msg_mat = self.initialState(msg)
        msg_key = self.addKey(msg_mat, subkey1)
        msg_enc = self.oneRound(msg_key, subkey2)

        msg_enc_hex = self.toHex(msg_enc)
        with open(opts.output, 'w') as f:
            f.write(msg_enc_hex)
        return msg_enc_hex

    def decrypt(self):
        subkey1, subkey2 = loadKey(opts.keyPath)
        return msg_dec

    def func_g(self, input, round=0):
        # 1-byte left circular rotation
        # the input here is a word, so it is a list
        recon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
        new_inp = list(input[1:])
        new_inp.append(input[0])
        # perform subBytes on each byte
        sbox = tables.getSbox()
        afterSBox = []
        for item in new_inp:
            index_value = item
            new_value = sbox[index_value]
            afterSBox.append(new_value)
        # xor the bytes with a round constant
        recon_val = [recon[round], 0x00, 0x00, 0x00]
        rtn = XOR(afterSBox, recon_val)
        return rtn

    def subKeySchedule(self, key_inp):
        def formNewKey(inp1, inp2, inp3, inp4):
            # all input are list with decimal format
            tmp0 = list2str(inp1)
            tmp1 = list2str(inp2)
            tmp2 = list2str(inp3)
            tmp3 = list2str(inp4)
            rtn = '0x' + ''.join(tmp0) + ''.join(tmp1) + ''.join(tmp2) + ''.join(tmp3)
            return rtn

        def getWordSet(keyMat):
            # take in key matrix, return words, all in decimal format
            new_mat = keyMat.T
            return new_mat[0], new_mat[1], new_mat[2], new_mat[3]

        w0, w1, w2, w3 = getWordSet(key_inp)
        #w4, w5, w6, w7 = getWordSet(subkey2)
        gx = self.func_g(w3)
        w4 = XOR(gx, w0)
        w5 = XOR(w4, w1)
        w6 = XOR(w5, w2)
        w7 = XOR(w6, w3)
        new_key = formNewKey(w4, w5, w6, w7)
        with open(opts.newkey, 'w') as f:
            f.write(new_key)
        return new_key


def main(opts):
    aes = AES()
    if 'enc' == opts.func:
        msg_enc = aes.encrypt(opts)
        print(msg_enc)
    elif 'dec' == opts.func:
        msg_dec = aes.decrypt(opts)
        print(msg_dec)
    elif 'keygen' == opts.func:
        # loadKey will return a key matrix
        subkey1, _ = loadKey(opts.keyPath)
        new_key = aes.subKeySchedule(subkey1)
        print(new_key)
    else:
        raise ValueError('no such option: {}'.format(opts.func))


def parseOpts(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--func', help='choose from enc/dec/keygen')
    parser.add_argument('-m', '--msgPath', help='path to msg file')
    parser.add_argument('-k', '--keyPath', help='path to key file')
    parser.add_argument('-o', '--output', default='../data/result.txt', help='path to store cipher')
    parser.add_argument('-n', '--newkey', default='../data/result_subkey.txt', help='path to store new key')
    opts = parser.parse_args()
    return opts


if __name__ == "__main__":
    opts = parseOpts(sys.argv)
    main(opts)