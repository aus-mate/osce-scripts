#!/usr/bin/python3
from boofuzz import *
import argparse

# Arguments 
arg = argparse.ArgumentParser(description="Template HTTP Fuzzer For OSCE")
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

    # GET /topology/home HTTP/1.1
    # Host: 192.168.100.185:7510
    # User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
    # Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    # Accept-Language: en-US,en;q=0.5
    # Accept-Encoding: gzip, deflate
    # Connection: close
    # Upgrade-Insecure-Requests: 1    


    # Initialize and define protocol messages
    s_initialize("get_top_home")

    if s_block_start("get_top_home"):
        s_string("GET", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("/topology/home", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("HTTP/1.1", fuzzable=False)
        s_string("\r\n", fuzzable=False)

        s_string("HOST:", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("192.168.100.185", fuzzable=True)
        s_delim(":", fuzzable=False)
        s_string("7510", fuzzable=True)
        s_string("\r\n", fuzzable=False)

        s_string("User-Agent:", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0", fuzzable=False)
        s_string("\r\n", fuzzable=False)

        s_string("Accept:", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", fuzzable=False)
        s_string("\r\n", fuzzable=False)
        
        s_string("Accept-Language:", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("en-US,en;q=0.5", fuzzable=False)
        s_string("\r\n", fuzzable=False)       

        s_string("Accept-Encoding:", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("gzip, deflate", fuzzable=False)
        s_string("\r\n", fuzzable=False)

        s_string("Connection:", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("close", fuzzable=False)
        s_string("\r\n", fuzzable=False)

        s_string("Upgrade-Insecure-Requests:", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("1", fuzzable=False)
        s_string("\r\n", fuzzable=False)

        s_string("\r\n", fuzzable=False)

        s_block_end()

    # Define the sequence of messages
    session.connect(s_get("get_top_home"))

    # Begin fuzzing
    session.fuzz()

if __name__ == "__main__":
    main()