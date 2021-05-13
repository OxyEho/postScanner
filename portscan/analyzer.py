import struct


class Analyzer:

    def __init__(self, port: int, proto: str, data: bytes = b'',
                 own_packet: bytes = b'', mask: str = '', app_proto: str = ''):
        self.port = port
        self.proto = proto
        self.data = data
        self.app_proto = app_proto
        self.own_packet = own_packet
        self.mask = mask
        if proto == 'TCP':
            self._check_tcp_app_proto()
        elif proto == 'UDP':
            self._check_udp_app_proto()

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

    def _check_udp_app_proto(self):
        try:
            data = struct.unpack(self.mask, self.data)
            if self.app_proto == 'DNS':
                own_data = struct.unpack(self.mask, self.own_packet)
                if own_data[0] != data[0]:
                    self.app_proto = ''
        except struct.error:
            self.app_proto = ''
