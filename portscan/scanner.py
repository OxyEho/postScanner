import socket


from multiprocessing.pool import ThreadPool
from multiprocessing import Lock
from queue import Queue, Empty


from portscan.analyzer import Analyzer
from portscan.packets import get_sntp_packet, get_dns_pack


class Scanner:

    lock = Lock()

    def __init__(self, ip: str, is_udp: bool, is_tcp: bool, ports: tuple):
        self.ip = socket.gethostbyname(ip)
        self.is_udp = is_udp
        self.is_tcp = is_tcp
        self.ports = tuple(int(x) for x in ports)
        self.thread_pool = ThreadPool(processes=10)
        self.result_queue = Queue()
        self.is_over = False
        self.udp_dict = {}
        self.tcp_dict = {}
        self.res_dict = {}

    def _check_tcp_port(self, port: int):
        with(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(0.5)
            try:
                res_of_con = sock.connect_ex((self.ip, port))
                if not res_of_con:
                    sock.connect((self.ip, port))
                    try:
                        data = sock.recv(1024)
                    except socket.timeout:
                        sock.sendall('GET / HTTP/1.1\n\n'.encode())
                        data = sock.recv(1024)
                    if data:
                        self.result_queue.put(Analyzer(port, "TCP", data=data))
            except socket.error:
                pass

    def _check_udp_port(self, port: int):
        sntp_pack = get_sntp_packet()
        dns_pack = get_dns_pack()
        packets = {dns_pack: 'DNS', sntp_pack: 'SNTP', b'': ''}
        masks_pack = {sntp_pack: '!BBbbiiiIIIIIIII', b'': '', dns_pack: '!HHHHHH'}
        with(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
            sock.settimeout(3)
            for pack in packets:
                try:
                    sock.sendto(pack, (self.ip, port))
                    data, _ = sock.recvfrom(2048)
                    if data:
                        if packets[pack] == 'DNS':
                            self.result_queue.put(Analyzer(port, "UDP", data=data[:12],
                                                           own_packet=pack[:12],
                                                           mask=masks_pack[pack],  app_proto='DNS'))
                        elif packets[pack] == 'SNTP':
                            self.result_queue.put(Analyzer(port, "UDP", data=data,
                                                           own_packet=pack, mask=masks_pack[pack], app_proto='SNTP'))
                except socket.timeout:
                    pass
                    # print(port)
                except socket.error:
                    pass

    def run(self):
        try:
            processes = []
            for port in range(self.ports[0], self.ports[1] + 1):
                if self.is_tcp:
                    processes.append(self.thread_pool.apply_async(self._check_tcp_port, args=(port,)))
                if self.is_udp:
                    processes.append(self.thread_pool.apply_async(self._check_udp_port, args=(port,)))
                    # self._check_udp_port(port)
            for process in processes:
                process.wait()
            while not self.result_queue.empty():
                print(self.result_queue.get())

        finally:
            self.thread_pool.terminate()
            self.thread_pool.join()
