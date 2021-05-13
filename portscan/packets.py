import struct
import time


def get_sntp_packet() -> bytes:
    first_byte = struct.pack('!B', (0 << 6 | 3 << 3 | 4))
    stratum = struct.pack('!B', 1)
    poll = struct.pack('!b', 0)
    precision = struct.pack('!b', -20)
    delay = struct.pack('!i', 0)
    dispersion = struct.pack('!i', 0)
    serv_id = struct.pack('!i', 0)
    _time = get_time_bytes(time.time())
    return first_byte + stratum + poll + precision + delay + dispersion + serv_id + _time + _time + _time + _time


def get_time_bytes(_time):
    sec, mil_sec = [int(x) for x in str(_time).split('.')]
    return struct.pack('!II', sec, mil_sec)


def get_dns_pack() -> bytes:
    pack_id = struct.pack('!H', 20)
    flags = struct.pack('!H', 256)
    qd_count = struct.pack('!H', 1)
    an_count = struct.pack('!H', 0)
    ns_count = struct.pack('!H', 0)
    ar_count = struct.pack('!H', 0)
    header = pack_id + flags + qd_count + an_count + ns_count + ar_count
    domain = 'a.ru'
    sec_dom, first_dom = domain.split('.')
    mark_first = struct.pack('!H', len(sec_dom))
    byte_sec = struct.pack(f'!{len(sec_dom)}s', sec_dom.encode())
    mark_second = struct.pack('!H', 2)
    byte_first = struct.pack(f'!{len(first_dom)}s', first_dom.encode())
    q_type = struct.pack('!H', 1)
    q_class = struct.pack('!H', 1)
    packet = header + mark_first + byte_sec + mark_second + byte_first + struct.pack('!H', 0) + q_type + q_class
    return packet


# print(get_dns_pack())

