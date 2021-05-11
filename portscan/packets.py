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
