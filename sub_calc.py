#!/usr/bin/python3
import argparse
import random

arg = argparse.ArgumentParser(description="Generate SUB instructions for sub-encoding shellcode")
arg.add_argument("shellcode", action="store", help="shellcode to be sub-encoded")
arg.add_argument("-b", dest="badchars", action="store", default="\x00", help="badchars to avoid, format: \x00")
args = arg.parse_args()

# shellcode = b"\xaf\x75\xea\xaf\x75\xe7\xff\xe7"
shellcode = bytearray(args.shellcode, 'ISO-8859-1').decode('unicode-escape').encode('ISO-8859-1')

sc_len = len(shellcode)
if((sc_len % 4) != 0): # check we can subencode this shellcode
    print("Shellcode is not divisible 4.")
    exit()
reverse_sc = shellcode[::-1] # reverse the shellcode

hex_bytes = bytearray(4) # initialize bytearray
bytes_num = 0
iter_req = sc_len // 4 # determine how many iterations of 4 bytes we need to do

for x in range(iter_req): # for every 4 bytes
    for y in range(4):
        hex_bytes[y] = reverse_sc[y + bytes_num] # store next 4 bytes
    int_val = int.from_bytes(hex_bytes, byteorder='big', signed=False) # convert to int for subtraction
    start_val = (0 - int_val) & 0xffffffff # 0 - value
    column_A = start_val.to_bytes(4, byteorder='little', signed=False) # convert back to bytes
    column_B = bytearray(4) # initalize bytearrays
    column_C = bytearray(4)
    column_D = bytearray(4)
    cf = 0 # carry flag
    badchars = bytearray(args.badchars, 'ISO-8859-1').decode('unicode-escape').encode('ISO-8859-1')

    for i in range(len(column_A)):
        x = column_A[i]
        if(cf == 1): # handle carry
            x -= 1
            cf = 0
        if(x == 0): # handle null byte
            x = 256
            cf = 1 # set flag

        while(1):
            column_B[i] = random.randint(1, 252) # generate random numbers
            column_C[i] = random.randint(1, 252)
            column_D[i] = random.randint(1, 252)
            if (x == column_B[i] + column_C[i] + column_D[i]): # solve equation
                if(column_B[i] not in badchars and column_C[i] not in badchars and column_D[i] not in badchars): # check for bad chars
                    break

    sub_1 = column_B[::-1] # reverse the bytes
    sub_2 = column_C[::-1]
    sub_3 = column_D[::-1]
    print("\nCLEAR EAX")
    print("SUB EAX, " + "0x" + sub_1.hex()) # print SUB commands
    print("SUB EAX, " + "0x" + sub_2.hex())
    print("SUB EAX, " + "0x" + sub_3.hex())
    print("PUSH EAX")
    bytes_num += 4