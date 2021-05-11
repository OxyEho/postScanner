class Analyzer:

    def __init__(self, port: int, proto: str, udp_app_proto: str = '', data: bytes = b''):
        self.port = port
        self.proto = proto
        self.data = data
        self.app_proto = udp_app_proto
        if proto == 'TCP':
            self._check_tcp_app_proto()

    def __str__(self):
        return f"{self.proto.upper()}: {str(self.port)} {self.app_proto}"

    def _check_tcp_app_proto(self):
        data_str = self.data.decode('utf-8')
        if 'HTTP/1.1' in data_str:
            self.app_proto = 'HTTP'
        elif 'smtp' in data_str:
            self.app_proto = 'SMTP'
        elif 'IMAP' in data_str:
            self.app_proto = 'IMAP'
        elif 'OK' in data_str:
            self.app_proto = 'POP3'
