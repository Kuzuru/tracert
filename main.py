import argparse

import requests
import scapy.layers.inet
from scapy.all import *


def get_whois_data(ip_address):
    url = "https://ipwhois.app/json/{}".format(ip_address)
    try:
        response = requests.get(url)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(e)
        return None

    whois_data = response.json()

    return {
        "netname": whois_data.get("org"),
        "asn": whois_data.get("asn"),
        "country": whois_data.get("country"),
    }


def valid_ip(address):
    try:
        socket.inet_aton(address)
        return True
    except:
        return False


class Tracer:
    def __init__(self):
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("ip", help="URL or IP address of the target resource.")

    def traceroute(self, target, max_hops=30):
        try:
            target_ip = socket.gethostbyname(target)
            print(f"Start trace to {target} [{target_ip}] with max ttl={max_hops}\n")

            last_addr = None

            for i in range(1, max_hops + 1):
                pkt = scapy.layers.inet.IP(dst=target, ttl=i) / scapy.layers.inet.UDP(dport=33434)
                # Send the packet and get a response
                resp = sr1(pkt, verbose=0, timeout=2)
                if resp is None:
                    # No response for this value of i
                    print(f"{i}. *\n")
                elif resp.type == 3:
                    # We've reached the destination
                    if resp.src != last_addr:
                        print(f"{i}. {resp.src}")
                        self.print_whois_data(resp.src)
                        last_addr = resp.src
                    break
                else:
                    # We're in the middle somewhere
                    if resp.src != last_addr:
                        print(f"{i}. {resp.src}")
                        self.print_whois_data(resp.src)
                        last_addr = resp.src
        except Exception as e:
            print(f"Unexpected error occurred: {str(e)}\nPlease verify the input and retry as an administrator.")
            return None

    def print_whois_data(self, ip_address):
        whois_data = get_whois_data(ip_address)
        if whois_data:
            netname = whois_data.get("netname") or ""
            asn = whois_data.get("asn") or ""
            country = whois_data.get("country") or ""

            if valid_ip(ip_address):
                if ip_address.startswith("192.168") or ip_address.startswith("10."):
                    print("local")
                elif netname or asn or country:
                    print(f"{netname}, {asn}, {country}")
                else:
                    print("WHOIS data not found")
            print()

    def execute(self):
        args = self.parser.parse_args()
        if valid_ip(args.ip) or self.is_valid_hostname(args.ip):
            self.traceroute(args.ip)
        else:
            print(f"{args.ip} is invalid")

    @staticmethod
    def is_valid_hostname(hostname):
        if len(hostname) > 255:
            return False
        if hostname[-1] == ".":
            hostname = hostname[:-1]
        allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(allowed.match(x) for x in hostname.split("."))


if __name__ == "__main__":
    tracer = Tracer()
    tracer.execute()
