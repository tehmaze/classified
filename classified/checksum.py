# Python imports
import hashlib
import struct
from zlib import adler32, crc32


class Adler32(object):
    block_size = 64L
    digestsize = 4L
    digest_size = 4L
    name = 'adler32'

    def __init__(self, string=''):
        self.checksum = adler32(string)

    def update(self, string):
        self.checksum = adler32(string, self.checksum)

    def digest(self):
        return struct.pack('>L', self.checksum & 0xffffffff)

    def hexdigest(self):
        return '%08x' % (self.checksum & 0xffffffff,)


class CRC32(object):
    block_size = 64L
    digestsize = 4L
    digest_size = 4L
    name = 'crc32'

    def __init__(self, string=''):
        self.checksum = crc32(string)

    def update(self, string):
        self.checksum = crc32(string, self.checksum)

    def digest(self):
        return struct.pack('>L', self.checksum & 0xffffffff)

    def hexdigest(self):
        return '%08x' % (self.checksum & 0xffffffff,)


def new(algorithm, string=''):
    if algorithm == 'adler32':
        return Adler32(string)

    if algorithm == 'crc32':
        return CRC32(string)

    else:
        return hashlib.new(algorithm)
