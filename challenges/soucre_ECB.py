#!/usr/bin/env python3

from Crypto.Util.number import bytes_to_long
import requests

def oracle(padding):
    r = requests.get('http://aes.cryptohack.org/ecb_oracle/encrypt/'+ padding + '/')
    return r.json()['ciphertext']

def second_block(blocks):
        return blocks[32:64]

flag = ""
for _ in range(32):
        lookup_table = {}
        padding = ("A" * (31-_)) + flag

        for i in range(0x20, 0x7E):
                build_flag = padding + chr(i)
                blocks = oracle(hex(bytes_to_long(build_flag.encode()))[2:])
                lookup_table[second_block(blocks)] = chr(i)

        n = oracle(hex(bytes_to_long(("A" * (31-_)).encode()))[2:])
        flag += lookup_table[second_block(n)]
        print (flag)

        #if the flag is fully recoverd and it is actually shorter than full 32 chars
        if "}" in flag:
            break

print (flag)
