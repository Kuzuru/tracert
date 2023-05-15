import ipaddress
import os
import socket
import struct
import time

from ip_info import IPAddressEntry
from whois_info import WhoisInfoFetcher


class TraceRunner:
    def __init__(self, target_ip, max_hops):
        self.timeout = 30
        self.target_ip = target_ip
        self.max_hops = max_hops

    def execute_trace(self):
        trace_entries = []
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as tracer_socket:
            tracer_socket.settimeout(self.timeout)
            for ttl in range(1, self.max_hops + 1):
                tracer_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                tracer_socket.sendto(self._create_icmp_header(), (self.target_ip, 1))

                try:
                    data, _ = tracer_socket.recvfrom(1024)
                    ip_header = data[0:20]

                    ip_struct = struct.unpack('!BBHHHBBH4s4s', ip_header)
                    source_ip = socket.inet_ntoa(ip_struct[8])

                    entry = IPAddressEntry(ttl, source_ip)
                    entry.populate_whois_info()
                    print(entry)

                    if struct.unpack('BB', data[20:22])[0] == 0:
                        break
                except socket.error:
                    entry = IPAddressEntry(ttl, "*")
                    print(entry)

                trace_entries.append(entry)

            return trace_entries

    @staticmethod
    def _create_icmp_header():
        temp_header = struct.pack("bbHHh", 8, 0, 0, 0, 0)
        checksum = TraceRunner._compute_checksum(temp_header)
        return struct.pack("bbHHh", 8, 0, checksum, 0, 0)

    @staticmethod
    def _compute_checksum(packet):
        """
        Calculates checksum according RFC 792
        """
        checksum = 0

        for i in range(0, len(packet), 2):
            word = packet[i] + (packet[i + 1] << 8)
            checksum += word
            overflow = checksum >> 16
            while overflow > 0:
                checksum = (checksum & 0xFFFF) + overflow
                overflow = checksum >> 16

        return ~checksum & 0xFFFF


class TraceEntry:
    def __init__(self, hop_number: int, ip: str):
        self.hop_number = hop_number
        self.ip = ip
        self.net_name = None
        self.as_number = None
        self.country = None

    def __str__(self):
        if self.ip == "*":
            return f"{self.hop_number}. *"

        local = self._is_local()
        if local:
            return f"{self.hop_number}. local"

        data = [self.net_name, self.as_number[2:], self.country] if self.country != "EU" else [self.net_name,
                                                                                               self.as_number[2:]]
        return f"{self.hop_number}. {self.ip} {', '.join([i for i in data if i])}"

    def _is_local(self):
        segments = [int(x) for x in self.ip.split('.')]
        return (
                segments[0] == 10 or
                (segments[0] == 192 and segments[1] == 168) or
                (segments[0] == 100 and 64 <= segments[1] <= 127) or
                (segments[0] == 172 and 16 <= segments[1] <= 31)
        )


class IcmpUtils:
    @staticmethod
    def create_header():
        ICMP_ECHO_REQUEST = 8

        checksum = 0
        identifier = os.getpid() & 0xFFFF
        sequence_number = 1

        # struct.pack takes the following arguments:
        # - "!BBHHH": format string (B=unsigned char, H=unsigned short, !=network/big-endian byte order)
        # - ICMP_ECHO_REQUEST: type of message
        # - checksum: message checksum (0 for now, will be filled later)
        # - identifier and sequence_number: typically used for matching requests and replies
        header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, checksum, identifier, sequence_number)

        return header

    @staticmethod
    def create_payload():
        # payload is used to calculate the round trip time
        # it contains the time in seconds and microseconds since the epoch
        payload = struct.pack("!d", time.time())

        return payload


class Tracer:
    def __init__(self, target: str, max_hops: int = 30, timeout: int = 2):
        self.target = target
        self.max_hops = max_hops
        self.timeout = timeout

    def trace_route(self):
        target_ip = socket.gethostbyname(self.target)
        print(f"Tracing route to {self.target} [{target_ip}] with max hops={self.max_hops}")

        icmp_proto = socket.getprotobyname('icmp')
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_proto)
        sock.settimeout(self.timeout)

        entries = []

        for ttl in range(1, self.max_hops + 1):
            trace_entry = self._probe_with_ttl(sock, ttl, target_ip)
            entries.append(trace_entry)

            if trace_entry.ip == target_ip:
                break

        return entries

    def _probe_with_ttl(self, sock, ttl, target_ip):
        icmp_header = IcmpUtils.create_header()
        icmp_payload = IcmpUtils.create_payload()

        icmp_packet = icmp_header + icmp_payload
        sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        sock.sendto(icmp_packet, (target_ip, 0))

        try:
            packet_data, addr = sock.recvfrom(1024)
            ip = addr[0]

            entry = TraceEntry(ttl, ip)

            if ip != "*":
                # use WhoisInfoFetcher here instead of WhoisUtils
                entry.net_name, entry.country, entry.as_number = WhoisInfoFetcher.get_whois_info(ip)

            return entry
        except socket.timeout:
            return TraceEntry(ttl, "*")

    @staticmethod
    def is_private_ip(ip):
        return (
            ipaddress.ip_address(ip).is_private
        )
