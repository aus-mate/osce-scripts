#!/usr/bin/python3
import argparse
import random

arg = argparse.ArgumentParser(description="Maths helper - find two values that don't contain bad bytes than can add together to reach a desired value")
arg.add_argument("val", action="store", help="desired value - in decimal")
arg.add_argument("-b", dest="badchars", action="store", default="\x00", help="badchars to avoid, format: \x00")
args = arg.parse_args()

badchars = bytearray(args.badchars, 'ISO-8859-1').decode('unicode-escape').encode('ISO-8859-1')

desired_val = int(args.val)

b = random.randint(1, desired_val)
while(1):
    x = random.randint(1, desired_val-1)
    y = desired_val - x
    x_byte_flag = 1
    y_byte_flag = 1
    if x > 255:
        x_byte_flag = 2
    if y > 255:
        y_byte_flag = 2
    x = x.to_bytes(x_byte_flag, byteorder="big")
    y = y.to_bytes(y_byte_flag, byteorder="big")

    if(all(i not in x for i in badchars) and all(i not in y for i in badchars)):
        print("\n0x" + x.hex())
        print("0x" + y.hex())
        break
