import re
import socket

from IPAddressEntry import IPAddressEntry
from custom_tracer.network import Network


class RouteTool:
    def __init__(self):
        self.network = Network()

    def traceroute(self, host: str, hops: int):
        ip = socket.gethostbyname(host)
        print(f"Start trace to {host} [{ip}] with max ttl={hops}")
        if self._is_local(ip):
            print("Local addresses are not routable.")
            return ()
        trace = self._get_ip_entries(ip, hops)
        return self.fill_traceroute(trace)

    def run_whois(self, server: str, query: str) -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((server, 43))

        s.send((bytes(query, 'utf-8')) + b'\r\n')
        msg = ''
        while len(msg) < 10000:
            try:
                receive_data = str((s.recv(100)), encoding='utf-8')
                if receive_data == '':
                    break
                msg = msg + receive_data
            except:
                pass
        s.close()
        return msg

    def get_whois_data(self, ip: str, whois: str = 'whois.iana.org', is_main=True):
        servs = ("whois.arin.net", "whois.lacnic.net", "whois.ripe.net", "whois.afrinic.net", "whois.apnic.net")

        msg = self.run_whois(whois, ip)
        net_name = ""
        country = ""
        as_number = ""

        # print(f"\nWhois data for {ip} from {whois}:\n{msg}\n")

        for line in msg.splitlines():
            if line.startswith("whois"):
                return self.get_whois_data(ip, line.split(':')[1].strip(), False)
            if re.match(re.compile(r"^[Nn]et[Nn]ame"), line) is not None:
                net_name = line.split(':')[1].strip()
            if re.match(re.compile(r"^[Cc]ountry"), line) is not None:
                country = line.split(':')[1].strip()
            if line.startswith("origin") or line.startswith("OriginAS"):
                as_number = line.split(':')[1].strip()

        if is_main and net_name == "" and country == "" and as_number == "":
            for s in servs:
                n_name, n_country, n_number = self.get_whois_data(ip, s, False)
                net_name = net_name if n_name == "" else n_name
                country = country if n_country == "" else n_country
                as_number = as_number if n_number == "" else n_number

        return net_name, country, as_number

    def _is_local(self, ip):
        segments = [int(x) for x in ip.split('.')]

        # 10.0.0.0 — 10.255.255.255
        if segments[0] == 10:
            return True
        # 192.168.0.0 — 192.168.255.255
        if segments[0] == 192 and segments[1] == 168:
            return True
        # 100.64.0.0 — 100.127.255.255
        if segments[0] == 100 and 127 >= segments[1] >= 64:
            return True
        # 172.16.0.0 — 172.31.255.255
        if segments[0] == 172 and 31 >= segments[1] >= 16:
            return True
        return False

    def fill_traceroute(self, entries):
        for entry in entries:
            net_name, country, as_number = self.get_whois_data(entry.ip)
            if net_name != "":
                entry.net_name = net_name
            if country != "":
                entry.country = country
            if as_number != "":
                entry.as_number = as_number
            yield entry

    def _get_ip_entries(self, ip: str, hops: int):
        number = 1
        for e in self.network.execute(ip, 1, hops):
            node, t, v = e
            entry = IPAddressEntry(number, node)
            number += 1
            yield entry
            if t == 0:
                return
            if number == hops:
                print("Exceeded the number of intermediate nodes")
                return
