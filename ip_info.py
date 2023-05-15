from whois_info import WhoisInfoFetcher


class IPAddressEntry:
    LOCAL_RANGES = [
        (10, 10),
        (192, 168),
        (100, 127),
        (172, 31),
    ]

    def __init__(self, number, ip):
        self.number = number
        self.ip = ip
        self.net_name = ""
        self.as_number = ""
        self.country = ""

    def __str__(self):
        if self.ip == "*":
            return f"{self.number}. {self.ip}\n"

        if self._is_local():
            return f"{self.number}. {self.ip}\nlocal\n"

        info = [self.net_name, self.as_number[2:], self.country]
        info = [i for i in info if i and i != "EU"]

        return f"{self.number}. {self.ip}\n{', '.join(info)}\n"

    def populate_whois_info(self):
        if self.ip != "*" and not self._is_local():
            self.net_name, self.country, self.as_number = WhoisInfoFetcher.get_whois_info(self.ip)

    def _is_local(self):
        segments = [int(x) for x in self.ip.split('.')]
        return any(segments[0] == start and start <= segments[1] <= end for start, end in self.LOCAL_RANGES)

    @staticmethod
    def is_local_address(ip):
        segments = [int(x) for x in ip.split('.')]
        return any(segments[0] == start and start <= segments[1] <= end for start, end in IPAddressEntry.LOCAL_RANGES)
