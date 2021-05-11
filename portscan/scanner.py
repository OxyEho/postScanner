import socket
import struct


from multiprocessing.pool import ThreadPool
from queue import Queue, Empty


from portscan.analyzer import Analyzer
from portscan.packets import get_sntp_packet


class Scanner:

    def __init__(self, ip: str, is_udp: bool, is_tcp: bool, ports: tuple):
        self.ip = socket.gethostbyname(ip)
        self.is_udp = is_udp
        self.is_tcp = is_tcp
        self.ports = tuple(int(x) for x in ports)
        self.thread_pool = ThreadPool(processes=10)
        self.result_queue = Queue()
        self.is_over = False

    def _check_tcp_port(self, port: int):
        with(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(0.5)
            print(port)
            try:
                res_of_con = sock.connect_ex((self.ip, port))
                if not res_of_con:
                    sock.connect((self.ip, port))
                    sock.sendall('GET / HTTP/1.1\n\n'.encode())
                    data = sock.recv(1024)
                    print(data)
                    self.result_queue.put(Analyzer(port, "TCP", data=data))
            except socket.error:
                print(port)
                pass
            finally:
                if port == self.ports[1]:
                    self.is_over = True

    def _check_udp_port(self, port: int):
        sntp_pack = get_sntp_packet()
        packets = {sntp_pack: 'SNTP', b'': ''}
        masks_pack = {sntp_pack: '!BBbbiiiIIIIIIII', b'': ''}
        with(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
            sock.settimeout(2)
            for pack in packets:
                try:
                    # sock.connect((self.ip, port))
                    sock.sendto(pack, (self.ip, port))
                    data, _ = sock.recvfrom(1024)
                    if data:
                        try:
                            print(struct.unpack(masks_pack[pack], data))
                            self.result_queue.put(Analyzer(port, "UDP", packets[pack]))
                        except struct.error:
                            self.result_queue.put(Analyzer(port, "UDP"))
                except socket.timeout:
                    print(port)
                except socket.error:
                    pass
                finally:
                    if port == self.ports[1]:
                        self.is_over = True

    def run(self):
        in_process_tcp = set()
        in_process_udp = set()
        try:
            port = self.ports[0]
            while not self.is_over:
                if self.is_tcp and port < self.ports[1] + 1 and port not in in_process_tcp:
                    self.thread_pool.apply_async(self._check_tcp_port, args=(port,))
                    in_process_tcp.add(port)
                if self.is_udp and port < self.ports[1] + 1 and port not in in_process_udp:
                    self.thread_pool.apply_async(self._check_udp_port, args=(port,))
                    in_process_udp.add(port)
                try:
                    res = self.result_queue.get(timeout=0.5)
                    print(res)
                except Empty:
                    pass
                if port < self.ports[1]:
                    port += 1
        finally:
            self.thread_pool.terminate()
            self.thread_pool.join()
