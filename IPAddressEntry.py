class IPAddressEntry:
    def __init__(self, number: int, ip: str):
        self.number = number
        self.ip = ip
        self.net_name = ""
        self.as_number = ""
        self.country = ""

    def __str__(self):
        result = f"{self.number}. {self.ip}\r\n"
        if self.ip == "*":
            return result
        if self._is_local():
            result += "local\r\n"
            return result
        data = []
        if self.net_name != "":
            data.append(self.net_name)
        if self.as_number != "":
            data.append(self.as_number[2:])
        if self.country != "" and self.country != "EU":
            data.append(self.country)
        return result + ", ".join(data) + "\r\n"

    def _is_local(self):
        segments = [int(x) for x in self.ip.split('.')]
        if segments[0] == 10:
            return True
        if segments[0] == 192 and segments[1] == 168:
            return True
        if segments[0] == 100 and (64 <= segments[1] <= 127):
            return True
        if segments[0] == 172 and (16 <= segments[1] <= 31):
            return True
        return False
