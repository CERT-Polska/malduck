# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

def asciiz(s):
    return s.split("\x00")[0]

def pad(s, block_size, style="pkcs7"):
    length = block_size - len(s) % block_size
    if length == block_size:
        padding = ""
    elif style == "pkcs7":
        padding = "%c" % length * length
    return s + padding
