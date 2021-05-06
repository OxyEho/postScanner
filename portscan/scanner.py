import socket


from multiprocessing.pool import ThreadPool
from queue import Queue, Empty


from portscan.analyzer import Analyzer


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
            sock.settimeout(1)
            try:
                res_of_con = sock.connect_ex((self.ip, port))
                if not res_of_con:
                    self.result_queue.put(Analyzer(port, "TCP", b''))
            except socket.error:
                print(port)
                pass
            finally:
                if port == self.ports[1]:
                    self.is_over = True
                sock.close()

    def _check_udp_port(self, port: int):

        for _ in range(2):
            with(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
                sock.settimeout(1)
                try:
                    sock.connect((self.ip, port))
                    sock.send(b'\x00')
                    data, _ = sock.recvfrom(1024)
                    self.result_queue.put(Analyzer(port, "UDP", data))
                except socket.timeout:
                    print(port)
                except socket.error:
                    break
                finally:
                    if port == self.ports[1]:
                        self.is_over = True
                    sock.close()

    def run(self):
        try:
            port = self.ports[0]
            while not self.is_over:
                if self.is_tcp and port != self.ports[1] + 1:
                    self.thread_pool.apply_async(self._check_tcp_port, args=(port,))
                if self.is_udp and port != self.ports[1] + 1:
                    self.thread_pool.apply_async(self._check_udp_port, args=(port,))
                try:
                    res = self.result_queue.get(timeout=1)
                    print(res)
                except Empty:
                    pass
                if port != self.ports[1]:
                    port += 1
        finally:
            self.thread_pool.terminate()
            self.thread_pool.join()
