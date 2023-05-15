import socket
import struct

from ip_info import IPAddressEntry


class TraceRunner:
    def __init__(self, target_ip, max_hops):
        self.target_ip = target_ip
        self.max_hops = max_hops

    def execute_trace(self):
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as tracer_socket:
            tracer_socket.settimeout(1)

            trace_entries = []
            for ttl in range(1, self.max_hops + 1):
                tracer_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                tracer_socket.sendto(self._create_icmp_header(), (self.target_ip, 1))

                try:
                    data, _ = tracer_socket.recvfrom(1024)
                    ip_header = data[0:20]

                    ip_struct = struct.unpack('!BBHHHBBH4s4s', ip_header)
                    source_ip = socket.inet_ntoa(ip_struct[8])

                    trace_entries.append(IPAddressEntry(ttl, source_ip))

                    if struct.unpack('BB', data[20:22])[0] == 0:
                        break
                except socket.error:
                    trace_entries.append(IPAddressEntry(ttl, "*"))

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
