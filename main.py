import argparse
import socket

from inet_util import TraceRunner
from ip_info import IPAddressEntry


def execute_traceroute(host, max_hops):
    ip_address = socket.gethostbyname(host)
    print(f"Tracing route to {host} [{ip_address}] with max hops={max_hops}")

    if IPAddressEntry.is_local_address(ip_address):
        print("Local addresses are not routed")
        return []

    tracer = TraceRunner(ip_address, max_hops)
    traceroute_entries = tracer.execute_trace()

    for entry in traceroute_entries:
        entry.populate_whois_info()

    return traceroute_entries


def display_traceroute(traceroute_entries):
    for entry in traceroute_entries:
        print(entry)


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("ip", help="The URL or IP address to trace")
    arg_parser.add_argument("--max_hops", help="Maximum number of hops", type=int, default=30)

    arguments = arg_parser.parse_args()

    try:
        traceroute_entries = execute_traceroute(arguments.ip, arguments.max_hops)
        display_traceroute(traceroute_entries)
    except Exception as e:
        print("Unexpected error occurred:", e)
        print("Please check the input and try again with administrator permissions")
