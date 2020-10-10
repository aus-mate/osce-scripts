#!/usr/bin/python3
from boofuzz import *
import argparse

# Arguments 
arg = argparse.ArgumentParser(description="Template TCP Fuzzer For OSCE")
arg.add_argument("host", action="store", help="Destination IP")
arg.add_argument("port", action="store", help="Destination port")
arg.add_argument("-s", action="store", default=0, dest="skip", help="Skip n tests - default 0")
arg.add_argument("-o", action="store", default="fuzz_results.csv", dest="outfile", help="CSV output file - default fuzz_results.csv")
args = arg.parse_args()

def main():
    csv_log = open('fuzz_results.csv', 'w')
    logger = [FuzzLoggerCsv(file_handle=csv_log)]
    
    # Define the session object
    session = Session(
        sleep_time=1,
        index_start=int(args.skip),
        fuzz_loggers=logger
    )
    
    # Define a target
    target = Target(connection = TCPSocketConnection(args.host, int(args.port)))
   
    # Add target to the session object
    session.add_target(target)

    # Initialize and define protocol messages
    s_initialize("TRUN")

    if s_block_start("TRUN"):
        s_string("TRUN", fuzzable=False)
        s_delim(" ", fuzzable=False)		
        s_string("FUZZ", fuzzable=True)
        s_block_end()

    # Define the sequence of messages
    session.connect(s_get("TRUN"))

    # Begin fuzzing
    session.fuzz()

if __name__ == "__main__":
    main()