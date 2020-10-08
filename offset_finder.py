import argparse
import re

arg = argparse.ArgumentParser(description='OSCE Exploit Template')
arg.add_argument("-q",dest="query",action="store",required=True,help="bytes to query")
arg.add_argument("pattern",action="store",help="cyclic pattern")
args = arg.parse_args()

print([x.start() for x in re.finditer(args.query, args.pattern, re.IGNORECASE)])