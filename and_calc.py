#!/usr/bin/python3
import argparse

arg = argparse.ArgumentParser(description="AND evaluate to 0")
arg.add_argument("hex", action="store", help="Hex to be AND'd to 0")
arg.add_argument("-b", dest="badchar", action="store", default="\x00", help="badchars to avoid, format: \x00")
args = arg.parse_args()

hex_val = int(args.hex, 16)
print("Calculating...")
x = 16843009 # Lowest 4 byte value with no null bytes
badchars = bytearray(args.badchar, 'ISO-8859-1').decode('unicode-escape').encode('ISO-8859-1')

while(1):
    if (hex_val & x == 0):
        match = bytes.fromhex('{:08x}'.format(x))
        if (all(i not in match for i in badchars)):
            break
    x +=1
print("Found hex value: " + hex(x))
