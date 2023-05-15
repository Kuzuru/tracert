import re
import socket


class WhoisInfoFetcher:
    WHOIS_SERVERS = ("whois.arin.net", "whois.lacnic.net", "whois.ripe.net", "whois.afrinic.net", "whois.apnic.net")
    MAIN_WHOIS = 'whois.iana.org'

    @staticmethod
    def get_whois_info(ip):
        whois_info = WhoisInfoFetcher._query_whois(ip, WhoisInfoFetcher.MAIN_WHOIS)

        if whois_info:
            return whois_info

        for server in WhoisInfoFetcher.WHOIS_SERVERS:
            whois_info = WhoisInfoFetcher._query_whois(ip, server)

            if whois_info:
                return whois_info

        return "", "", ""

    @staticmethod
    def _query_whois(ip, server):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((server, 43))
                s.sendall((ip + '\r\n').encode())
                response = s.recv(4096).decode()

            net_name = WhoisInfoFetcher._extract_info(response, r"^[Nn]et[Nn]ame")
            country = WhoisInfoFetcher._extract_info(response, r"^[Cc]ountry")
            as_number = WhoisInfoFetcher._extract_info(response, r"^origin|^OriginAS")

            if net_name or country or as_number:
                return net_name, country, as_number

            return None
        except:
            return None

    @staticmethod
    def _extract_info(response, pattern):
        match = re.search(pattern, response, re.MULTILINE)
        return match.group(1).strip() if match else ""
