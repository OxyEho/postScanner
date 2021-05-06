class Analyzer:

    def __init__(self, port: int, proto: str, data: bytes):
        self.port = port
        self.proto = proto
        self.data = data

    def __str__(self):
        return f"{self.proto.upper()}: {str(self.port)}"
