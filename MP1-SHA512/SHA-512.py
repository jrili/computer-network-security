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
import os
import sys

class SHA_512:
    def __init__(self, input_file_name, verbose_mode_active=False):
        self._reset()
        self._set_verbose_mode(verbose_mode_active)
        self.open_file(input_file_name)

    def _reset(self):
        self._input_file_name = None
        self._input_file_size_in_bytes = 0

        self._MSG_BLK_SIZE_IN_BITS = 1024
        self._MSG_BLK_SIZE_IN_BYTES = self._MSG_BLK_SIZE_IN_BITS >> 3
        self._MSG_BLKGRP_SIZE_IN_BITS = 64
        self._MSG_BLKGRP_SIZE_IN_BYTES = self._MSG_BLKGRP_SIZE_IN_BITS >> 3
        self._NUM_MSGBLKGRPS_PER_MSGBLK = int(self._MSG_BLK_SIZE_IN_BITS / self._MSG_BLKGRP_SIZE_IN_BITS)

    def _set_verbose_mode(self, verbose_mode_active):
        self._verbose_mode_active = verbose_mode_active
        if self._verbose_mode_active:
            self._print('Verbose mode activated')

    def _print(self, to_print, prefix='', severity='INF'):
        if severity != 'DBG' or (severity == 'DBG' and self._verbose_mode_active):
            print('%s%s: %s' % (prefix, severity, to_print))


    def open_file(self, input_file_name):
        if os.path.isfile(input_file_name):
            self._input_file_name = os.path.abspath(input_file_name)
            self._input_file_size_in_bytes = os.path.getsize(self._input_file_name)
            self._input_file_handler = open(self._input_file_name, 'rb')
            self._print('Input File "%s"(%d bytes) loaded!' % (self._input_file_name, self._input_file_size_in_bytes))
        else:
            self._print('Specified Input File "%s" not found!' % input_file_name, severity='ERR')

    def _pad_message(self, current_blkgrp_data, current_blkgrp_num, total_msg_len):
        for blkgrp_num in range(current_blkgrp_num, self._NUM_MSGBLKGRPS_PER_MSGBLK):
            current_blkgrp_data_int = int.from_bytes(current_blkgrp_data,byteorder='big')
            print(current_blkgrp_data_int<<BYHOWMUCH?)

    def _read_message_block(self):
        if self._input_file_name is not None:
            for msg_blkgrp_num in range(0,self._NUM_MSGBLKGRPS_PER_MSGBLK):
                blkgrp_data = self._input_file_handler.read(self._MSG_BLKGRP_SIZE_IN_BYTES)
                if len(blkgrp_data) < self._MSG_BLKGRP_SIZE_IN_BYTES:
                    self._pad_message(blkgrp_data, msg_blkgrp_num, self._input_file_size_in_bytes << 3)
                self._print('MSG BLKGRP #%d (%d bytes):' % (msg_blkgrp_num, len(blkgrp_data)) + str(binascii.hexlify(blkgrp_data)),
                            prefix='\t', severity='DBG')
        else:
            self._print('Reading message block failed: No file loaded yet!', severity='ERR')

if __name__ == '__main__':
    argparser = argparse.ArgumentParser()
    argparser.add_argument('input_file', help='filename of input')
    argparser.add_argument('-v', '--verbose', dest='verbose_mode', action='store_true', help='activate for verbose mode')
    args = argparser.parse_args()

    input_file_name = args.input_file
    hasher = SHA_512(input_file_name, args.verbose_mode)
    hasher._read_message_block()