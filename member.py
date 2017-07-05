class Member:
    def __init__(self, mac):
        """Initial Setting methid."""
        self.port = None
        self.mac = mac
        self.ip = None

    def toJson(self):
        return {"port": self.port,
                "mac": self.mac,
                "ip": self.ip}
