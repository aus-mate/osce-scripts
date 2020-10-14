#!/usr/bin/python3
import argparse
import random
import os

arg = argparse.ArgumentParser(description="Generate SUB instructions for sub-encoding shellcode BROKEN use sub_encoder")
arg.add_argument("shellcode", action="store", help="shellcode to be sub-encoded")
arg.add_argument("-b", dest="badchars", action="store", default="\x00", help="badchars to avoid")
arg.add_argument("-t", dest="targ_address", action="store", help="Target address of where decoded shellcode will be executed")
arg.add_argument("-e", dest="esp_initval", action="store", help="Initial address of ESP before decode")
args = arg.parse_args()

shellcode = bytearray(args.shellcode, 'ISO-8859-1').decode('unicode-escape').encode('ISO-8859-1')
sc_len = len(shellcode)
if((sc_len % 4) != 0): # check we can subencode this shellcode - if not apply nops?
    print("Shellcode is not divisible 4.")
    exit()
reverse_sc = shellcode[::-1] # reverse the shellcode

hex_bytes = bytearray(4) # initialize bytearray
encoded_shellcode = bytearray("", 'ISO-8859-1')
bytes_num = 0
iter_req = sc_len // 4 # determine how many iterations of 4 bytes we need to do

print("\nPUSH ESP\nPOP EAX")
encoded_shellcode += b"\x54\x58"


### we need to take the value of esp_initial and use subencode instructions to reach targ_address
start_val = (int(args.esp_initval, 16) - int(args.targ_address, 16)) & 0xffffffff # 0 - value
column_A = start_val.to_bytes(4, byteorder='little', signed=False) # convert to bytes
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
print("SUB EAX, " + "0x" + sub_1.hex()) # print SUB commands
print("SUB EAX, " + "0x" + sub_2.hex())
print("SUB EAX, " + "0x" + sub_3.hex())
encoded_shellcode += b"\x2d" + sub_1[::-1]
encoded_shellcode += b"\x2d" + sub_2[::-1]
encoded_shellcode += b"\x2d" + sub_3[::-1]

print("PUSH EAX\nPOP ESP")
encoded_shellcode += b"\x50\x5C"

### We need to clear EAX before the next SUB instructions
rand_and_val = bytearray(os.urandom(4))
while(1):
    rand_and_val = bytearray(os.urandom(4))
    if (all(i not in rand_and_val for i in badchars)):
        break
    
print("AND EAX, " + "0x" + rand_and_val.hex())
encoded_shellcode += b"\x25" + rand_and_val[::-1]

hex_val = int(args.esp_initval, 16)
and_val = hex_val & int.from_bytes(rand_and_val, byteorder='big', signed=False)

start_and_val = 16843009 # Lowest 4 byte value with no null bytes
while(1):
    if (and_val & start_and_val == 0):
        match = bytes.fromhex('{:08x}'.format(start_and_val))
        if (all(i not in match for i in badchars)):
            break
    start_and_val +=1
print("AND EAX, " + hex(start_and_val))
encoded_shellcode += b"\x25" + start_and_val.to_bytes(4, 'little')




for j in range(iter_req): # for every 4 bytes of shellcode
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
    print("SUB EAX, " + "0x" + sub_1.hex()) # print SUB commands
    print("SUB EAX, " + "0x" + sub_2.hex())
    print("SUB EAX, " + "0x" + sub_3.hex())
    print("PUSH EAX")
    encoded_shellcode += b"\x2d" + sub_1[::-1] # SUB EAX commands
    encoded_shellcode += b"\x2d" + sub_2[::-1]
    encoded_shellcode += b"\x2d" + sub_3[::-1]
    encoded_shellcode += b"\x50" # PUSH EAX

    ### CALCULATE NEXT AND VALUE TO RESET EAX TO 0
    if (j == iter_req-1): # skip last AND instructions
        break
    rand_and_val = bytearray(os.urandom(4))
    while(1):
        rand_and_val = bytearray(os.urandom(4))
        if (all(i not in rand_and_val for i in badchars)):
            break
    
    print("AND EAX, " + "0x" + rand_and_val.hex())
    encoded_shellcode += b"\x25" + rand_and_val[::-1]

    hex_val = int.from_bytes(hex_bytes, byteorder='big', signed=False)
    and_val = hex_val & int.from_bytes(rand_and_val, byteorder='big', signed=False)
    
    start_and_val = 16843009 # Lowest 4 byte value with no null bytes
    while(1):
        if (and_val & start_and_val == 0):
            match = bytes.fromhex('{:08x}'.format(start_and_val))
            if (all(i not in match for i in badchars)):
                break
        start_and_val +=1
    print("AND EAX, " + hex(start_and_val))
    encoded_shellcode += b"\x25" + start_and_val.to_bytes(4, 'little')

    bytes_num += 4 # on to the next 4 bytes

print("\nEncoded payload: " + "\"" + "".join("\\x%02x" % i for i in encoded_shellcode) + "\"")