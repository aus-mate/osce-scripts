#!/usr/bin/python3
from boofuzz import *
import argparse

# Arguments 
arg = argparse.ArgumentParser(description="Template FTP Fuzzer For OSCE")
arg.add_argument("host", action="store", help="Destination IP")
arg.add_argument("-p", action="store", dest="port", required=True, help="Destination port")
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
        fuzz_loggers=logger,
        receive_data_after_fuzz=True
    )
    
    # Define a target
    target = Target(connection = TCPSocketConnection(args.host, int(args.port)))
   
    # Add target to the session object
    session.add_target(target)

    # Initialize and define protocol messages
    s_initialize("USER")

    if s_block_start("USER"):
        s_string("USER", fuzzable=False)
        s_delim(" ", fuzzable=False)		
        s_string("anonymous", fuzzable=True)
        s_static("\r\n")
        s_block_end()
    
    s_initialize("PASS")

    if s_block_start("PASS"):
        s_string("PASS", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("password", fuzzable=True)
        s_static("\r\n")

    s_initialize("STOR")

    if s_block_start("STOR"):
        s_string("STOR", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("FUZZ", fuzzable=True)
        s_static("\r\n")

    s_initialize("RETR")

    if s_block_start("RETR"):
        s_string("RETR", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("FUZZ", fuzzable=True)
        s_static("\r\n")


    s_initialize("ABOR")

    if s_block_start("ABOR"):
        s_string("ABOR", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("FUZZ", fuzzable=True)
        s_static("\r\n")

    # Define the sequence of messages
    session.connect(s_get("USER"))
    session.connect(s_get("USER"), s_get("PASS"))
    session.connect(s_get("PASS"), s_get("ABOR"))
    session.connect(s_get("PASS"), s_get("STOR"))
    session.connect(s_get("PASS"), s_get("RETR"))

    # Begin fuzzing
    session.fuzz()

if __name__ == "__main__":
    main()