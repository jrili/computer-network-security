'''
EE298 K - COMPUTER NETWORK SECURITY
SHA-512 IMPLEMENTATION

CODE SUBMITTED BY:
JESSA RILI
KIRSTEN HIPOLITO
KARYN MAGLALANG

REQUIREMENTS:
    python 3.6.x
'''
import binascii
import argparse
import numpy as np
import os
import sys

class SHA_512:
    def __init__(self, input_file_name, verbose_mode_active=False):
        self._set_verbose_mode(verbose_mode_active)
        self._reset()
        self.open_file(input_file_name)

    def _set_registers(self, values):
        index = 0
        for key in self._registers:
            self._registers[key] = values[index]
            index += 1

        log = 'Registers have been set: ', [(key, hex(self._registers[key])) for key in self._registers]
        self._print(log, severity='DBG', prefix='\t')

    def _reset(self):
        self._input_file_name = None
        self._input_file_size_in_bytes = 0
        self._BYTE_ORDER = 'big'

        self._MSG_BLK_SIZE_IN_BITS = 1024
        self._MSG_BLK_SIZE_IN_BYTES = self._MSG_BLK_SIZE_IN_BITS >> 3
        self._MSG_BLKGRP_SIZE_IN_BITS = 64
        self._MSG_BLKGRP_SIZE_IN_BYTES = self._MSG_BLKGRP_SIZE_IN_BITS >> 3
        self._NUM_MSGBLKGRPS_PER_MSGBLK = int(self._MSG_BLK_SIZE_IN_BITS / self._MSG_BLKGRP_SIZE_IN_BITS)
        self._MSGLEN_SIZE_IN_BITS = 128
        self._MSGLEN_SIZE_IN_BYTES = self._MSGLEN_SIZE_IN_BITS >> 3

        ''' Last block containing 112B of 0's and the 16B (128bits) of total msg len in bits '''
        self._pad_and_msglen_blk = []

        self._eof_reached = False

        self._hash =\
        [
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179
        ]

        self._registers = {'a':0, 'b':0, 'c':0, 'd':0, 'e':0, 'g':0, 'g':0, 'h':0}
        self._set_registers(self._hash)

        self._K = \
        [
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
        ]

    def _set_verbose_mode(self, verbose_mode_active):
        self._verbose_mode_active = verbose_mode_active
        if self._verbose_mode_active:
            self._print('Verbose mode activated')

    def _print(self, to_print, prefix='', severity='INF'):
        if severity != 'DBG' or (severity == 'DBG' and self._verbose_mode_active):
            print('%s%s: %s' % (prefix, severity, to_print))

    def _print_msgblk(self, msg_blk):
        print(msg_blk)
        self._print('Displaying current message block:', severity='DBG')
        for msg_blkgrp_num, msg_blkgrp in enumerate(msg_blk):
            self._print('MSG BLKGRP #%d (%d bytes):' % (msg_blkgrp_num, len(msg_blkgrp)) + str(binascii.hexlify(msg_blkgrp)),
                        prefix='\t', severity='DBG')
    ''' SIX LOGICAL FUNCTIONS AS DEFNINED IN SHA-512 DOCUMENT'''
    def _Ch(self, x, y, z):
        return (x & y) ^ (~x & z)

    def _Maj(self, x, y, z):
        return (x & y) ^ (x & z) ^ (y & z)

    def _bitrotate_right(self, x, bits):
        NUM_INT_BITS = 64
        INT_MASK = (2**NUM_INT_BITS) - 1
        return ((x >> bits) | (x << (NUM_INT_BITS - bits))) & INT_MASK

    def _bigsigma0(self, x):
        return self._bitrotate_right(x, 28) ^ self._bitrotate_right(x, 34) ^ self._bitrotate_right(x, 39)

    def _bigsigma1(self, x):
        return self._bitrotate_right(x, 14) ^ self._bitrotate_right(x, 18) ^ self._bitrotate_right(x, 41)

    def _sigma0(self, x):
        # print('SIGMA0: x=%#x ; ROT1(x)=%#x ; ROT8(x)=%#x ; x>>7=%#x' % (x,self._bitrotate_right(x, 1), self._bitrotate_right(x, 8), (x >> 7)))
        return self._bitrotate_right(x, 1) ^ self._bitrotate_right(x, 8) ^ (x >> 7)

    def _sigma1(self, x):
        return self._bitrotate_right(x, 19) ^ self._bitrotate_right(x, 61) ^ (x >> 6)

    ''' SIX LOGICAL FUNCTIONS END'''

    def open_file(self, input_file_name):
        if os.path.isfile(input_file_name):
            self._input_file_name = os.path.abspath(input_file_name)
            self._input_file_size_in_bytes = os.path.getsize(self._input_file_name)
            self._input_file_size_in_bits = self._input_file_size_in_bytes << 3
            self._input_file_handler = open(self._input_file_name, 'rb')
            self._print('Input File "%s"(%d bytes) loaded!' % (self._input_file_name, self._input_file_size_in_bytes))
        else:
            self._print('Specified Input File "%s" not found!' % input_file_name, severity='ERR')

    def _pad_message(self, current_blkgrp_data, current_blkgrp_num, total_msg_len):

        inputfilesize_bytes = bytearray(self._input_file_size_in_bits.to_bytes(self._MSGLEN_SIZE_IN_BYTES,
                                                                               byteorder=self._BYTE_ORDER))
        log = 'INPUTFILESIZE "L=%d" IN MSG: ' % (self._input_file_size_in_bits), inputfilesize_bytes
        self._print(log, severity='INF', prefix='\t')

        pad_len_in_bytes = self._MSG_BLK_SIZE_IN_BYTES - self._MSGLEN_SIZE_IN_BYTES
        current_remaining_num_blkgrp = self._NUM_MSGBLKGRPS_PER_MSGBLK - current_blkgrp_num

        if current_remaining_num_blkgrp*self._MSG_BLKGRP_SIZE_IN_BYTES > (self._MSGLEN_SIZE_IN_BYTES + 1):
            ''' Append pad bits to this current msg block'''
            pad_len_in_bytes -= (self._NUM_MSGBLKGRPS_PER_MSGBLK - current_remaining_num_blkgrp)*self._MSG_BLKGRP_SIZE_IN_BYTES + len(current_blkgrp_data)
        else:
            ''' Need to create a separate msg block for the pad bits alone'''
            pad_len_in_bytes += current_remaining_num_blkgrp * self._MSG_BLKGRP_SIZE_IN_BYTES - len(current_blkgrp_data)


        self._print('PAD_LEN_IN_BYTES: %d' % (pad_len_in_bytes), severity='DBG', prefix='\t')
        pad_bytes = bytearray([0x80] + [0x00] * (pad_len_in_bytes - 1))

        last_blk = current_blkgrp_data + pad_bytes + inputfilesize_bytes
        log = 'PADDED MSG BLKGRPS (len=%d bytes):' % (len(last_blk)), last_blk
        self._print(log, severity='DBG', prefix='\t')

        padded_blkgrps = []

        ''' CHOP IT UP INTO 64-bit MSG BLKGRPS '''
        for blkgrp_num in range(0, int(len(last_blk)/self._MSG_BLKGRP_SIZE_IN_BYTES)):
            start = (blkgrp_num)*self._MSG_BLKGRP_SIZE_IN_BYTES
            end = start + self._MSG_BLKGRP_SIZE_IN_BYTES
            padded_blkgrps.append(last_blk[start:end])

        padded_remaining_msg_blkgrps = padded_blkgrps[0:self._NUM_MSGBLKGRPS_PER_MSGBLK-current_blkgrp_num]
        log = 'PADDED REMAINING MSG BLOCK GROUPS(%d BLKGRPS):' % (len(padded_remaining_msg_blkgrps)), padded_remaining_msg_blkgrps
        self._print(log, severity='DBG', prefix='\t')

        pad_and_msglen_blkgrps = padded_blkgrps[self._NUM_MSGBLKGRPS_PER_MSGBLK-current_blkgrp_num:]
        log = 'PAD+MSGLEN MSG BLOCK GROUPS(%d BLKGRPS):' % (len(pad_and_msglen_blkgrps)), pad_and_msglen_blkgrps
        self._print(log, severity='DBG', prefix='\t')

        return padded_remaining_msg_blkgrps, pad_and_msglen_blkgrps

    '''
    METHOD: _read_message_block
    INPUT: N/A
    OUTPUT: a list of 16 bytearrays
    DESCRIPTION:
        Reads the next message block in the input file, returns it as a list of 8-byte(64-bit) bytearrays
        Will pad the data as needed. 
    
    '''
    def _read_message_block(self):
        msg_blk = []
        if self._pad_and_msglen_blk != []:
            msg_blk = self._pad_and_msglen_blk.copy()
            self._pad_and_msglen_blk = []
            self._eof_reached = True
        elif self._input_file_name is not None:
            for msg_blkgrp_num in range(0, self._NUM_MSGBLKGRPS_PER_MSGBLK):
                blkgrp_data = self._input_file_handler.read(self._MSG_BLKGRP_SIZE_IN_BYTES)
                if len(blkgrp_data) < self._MSG_BLKGRP_SIZE_IN_BYTES:
                    self._print('Generating pad bits...', severity='DBG', prefix='\t')
                    padded_remaining_msg_blkgrps, pad_and_msglen_blk = \
                        self._pad_message(blkgrp_data, msg_blkgrp_num, self._input_file_size_in_bytes << 3)
                    msg_blk += padded_remaining_msg_blkgrps
                    if pad_and_msglen_blk:
                        print('Left-over pad bits set')
                        self._pad_and_msglen_blk = pad_and_msglen_blk
                    else:
                        print('EOF reached')
                        self._eof_reached = True
                    break
                msg_blk.append(blkgrp_data)
        else:
            self._print('Reading message block failed: No file loaded yet!', severity='ERR')

        return msg_blk

    def _sum_list(self, list1, list2):
        num_elements = min(len(list1), len(list2))
        sums = []
        for i in range(0, num_elements):
            sums.append(list1[i] + list2[i])
        return sums

    def _compute_updated_register_values(self, K, W):
        a=0; b=0; c=0; d=0; e=0; f=0; g=0; h=0
        for j in range(0, 80):
            T1 = self._registers['h'] + self._bigsigma1(self._registers['e']) +\
                 self._Ch(self._registers['e'], self._registers['f'], self._registers['g']) + K[j] + W[j]

            #TODO

        return [a, b, c, d, e, f, h]

    def _compute_expanded_msgblocks(self, msg_block):
        W = [0]*80
        for i in range(0, 16):
            W[i] = int.from_bytes(msg_block[i], byteorder=self._BYTE_ORDER)

        for j in range(16, 80):
            W[j] = self._sigma1(W[j-2]) + W[j-7] + self._sigma0(W[j-15]) + W[j-16]

        self._print('W:'+str([hex(x) for x in W]), prefix='\t')
        return W

    def _compute_hash_for_msgblock(self, msg_block):
        log = 'CURRENT HASH VALUE(BEFORE COMPUTE):', [hex(x) for x in self._hash]
        self._print(log, prefix='\t')

        ''' INITIALIZE '''
        self._set_registers(self._hash)
        W = self._compute_expanded_msgblocks(msg_block)

        self._set_registers(self._compute_updated_register_values(self._K, W))

        self._hash = self._sum_list(self._hash, list(self._registers.values()))
        log = 'CURRENT HASH VALUE(AFTER COMPUTE):', [hex(x) for x in self._hash]
        self._print(log, prefix='\t')


    def compute(self):
        current_block_num = 1
        while(self._eof_reached == False):
            print('\n\n')
            self._print('Processing Block#%d'%(current_block_num))
            current_msg_block = self._read_message_block()
            self._print_msgblk(current_msg_block)

            self._compute_hash_for_msgblock(current_msg_block)

            self._print('Processing Block#%d: done!'%(current_block_num))
            current_block_num += 1

        self._reset()
        self._input_file_handler.close()

if __name__ == '__main__':
    argparser = argparse.ArgumentParser()
    argparser.add_argument('input_file', help='filename of input')
    argparser.add_argument('-v', '--verbose', dest='verbose_mode', action='store_true', help='activate for verbose mode')
    args = argparser.parse_args()

    input_file_name = args.input_file
    hasher = SHA_512(input_file_name, args.verbose_mode)
    hasher.compute()
