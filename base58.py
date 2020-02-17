'''Base58 encoding

Implementations of Base58 and Base58Check encodings that are compatible
with the bitcoin network.
'''

# Copyright (c) 2015 David Keijser
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# This module is based upon base58 snippets found scattered over many bitcoin
# tools written in python. From what I gather the original source is from a
# forum post by Gavin Andresen, so direct your praise to him.
# This module adds shiny packaging and support for python3.

from hashlib import sha256
from binascii import unhexlify

__version__ = '1.0.3'

# 58 character alphabet used
alphabet = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def b58encode_int(i):
    '''Encode an integer using Base58'''
    string = b""
    while i:
        i, idx = divmod(i, 58)
        string = alphabet[idx:idx+1] + string
    return string


def b58encode(v):
    '''Encode a string using Base58'''
    nPad = len(v)
    v = v.lstrip(b'\0')
    nPad -= len(v)

    p, acc = 1, 0
    for c in reversed(v):
        acc += p * c
        p = p << 8

    result = b58encode_int(acc)

    return (alphabet[0:1] * nPad + result)


def b58encode_check(v):
    '''Encode a string using Base58 with a 4 character checksum'''

    digest = sha256(sha256(v).digest()).digest()
    return b58encode(v + digest[:4])

class Base58Error(Exception):
    pass

class InvalidBase58Error(Base58Error):
    """Raised on generic invalid base58 data, such as bad characters.

    Checksum failures raise Base58ChecksumError specifically.
    """
    pass

def b58decode(s):
    """Decode a base58-encoding string, returning bytes"""
    if not s:
        return b''

    # Convert the string to an integer
    n = 0
    for c in s:
        n *= 58
        if ord(c) not in alphabet:
            raise InvalidBase58Error('Character %r is not a valid base58 character' % c)
        digit = alphabet.index(ord(c))
        n += digit

    # Convert the integer to bytes
    h = '%x' % n
    if len(h) % 2:
        h = '0' + h
    res = unhexlify(h.encode('utf8'))

    # Add padding back.
    pad = 0
    for c in s[:-1]:
        if ord(c) == alphabet[0]: pad += 1
        else: break
    return b'\x00' * pad + res
