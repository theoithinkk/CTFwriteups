"""Silent Breaker solver: SS7 OTP interception -> OT-VPN -> IEC-104 breaker command.

Usage: python -I solve.py http://HOST:PORT

Every launch is a new case, so nothing is hardcoded:
1. Pull the case files and the signalling feed.
2. Rogue GT (outside GT-0000..GT-0999) -> MSISDNs it probed -> the one roster employee
   with OT-VPN access. Confirm them, which unlocks the VPN window -> their session id.
3. Parse the pcap by hand (stdlib only): the C_SC_NA_1 / C_DC_NA_1 activation gives the
   IOA, ON/OFF and wire time; M_ME_NC_1 floats give the live current.
4. Historian SUSPECT run on that IOA, in 150-550 A and >5 A away from live = frozen value.
5. POST the report.
"""
import json
import re
import struct
import sys
import urllib.request
from datetime import datetime, timezone

BASE = sys.argv[1].rstrip('/') if len(sys.argv) > 1 else ''


def get(path, raw=False):
    with urllib.request.urlopen(BASE + path, timeout=15) as r:
        data = r.read()
    return data if raw else json.loads(data)


def post(path, body):
    req = urllib.request.Request(BASE + path, json.dumps(body).encode(),
                                 {'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def iec104_asdus(pcap):
    """Yield (utc datetime, src ip, asdu bytes) for every I-format APDU in a classic Ethernet pcap."""
    assert pcap[:4] == b'\xd4\xc3\xb2\xa1', 'expected little-endian classic pcap'
    off = 24
    while off + 16 <= len(pcap):
        sec, usec, incl, _ = struct.unpack_from('<IIII', pcap, off)
        pkt = pcap[off + 16: off + 16 + incl]
        off += 16 + incl
        if pkt[12:14] != b'\x08\x00' or pkt[23] != 6:          # IPv4 + TCP only
            continue
        ihl = (pkt[14] & 0x0F) * 4
        tcp = 14 + ihl
        payload = pkt[tcp + (pkt[tcp + 12] >> 4) * 4:]
        src = '.'.join(map(str, pkt[26:30]))
        ts = datetime.fromtimestamp(sec + usec / 1e6, timezone.utc)
        i = 0
        while i + 6 <= len(payload) and payload[i] == 0x68:   # APDU: 0x68, len, 4 control bytes
            ln = payload[i + 1]
            if payload[i + 2] & 1 == 0:                        # I-format carries an ASDU
                yield ts, src, payload[i + 6: i + 2 + ln]
            i += 2 + ln


def parse_pcap(pcap):
    cmd, live = None, {}
    for ts, src, a in iec104_asdus(pcap):
        typ, cot = a[0], a[2] & 0x3F
        ioa = a[6] | a[7] << 8 | a[8] << 16
        if typ == 13:                                          # M_ME_NC_1 short float
            live[ts.replace(microsecond=0)] = struct.unpack_from('<f', a, 9)[0]
        elif typ in (45, 46) and cot == 6 and cmd is None:     # first command activation
            q = a[9]
            state = ('ON' if q & 1 else 'OFF') if typ == 45 else {1: 'OFF', 2: 'ON'}.get(q & 3, '?')
            cmd = dict(ioa=ioa, qualifier=state, time=ts, src=src)
    return cmd, live


def frozen_value(log, ioa, live):
    """SUSPECT historian value on the commanded IOA that is in range and >5 A off the live RTU value."""
    hits = set()
    for t, i, v in re.findall(r'^(\S+Z) IOA=(0x[0-9a-f]+) VALUE=([\d.]+)A QUALITY=SUSPECT', log, re.M | re.I):
        ts = datetime.strptime(t, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        v = float(v)
        near = min(live, key=lambda k: abs((k - ts).total_seconds()))
        if int(i, 16) == ioa and 150.0 <= v <= 550.0 and abs(v - live[near]) > 5.0:
            hits.add(v)
    assert len(hits) == 1, hits
    return hits.pop()


def demo():
    # One C_SC_NA_1 activation (SCO=1 -> ON) on IOA 0x2cbd, wrapped in Ethernet/IPv4/TCP/pcap.
    asdu = bytes([45, 1, 6, 0, 1, 0, 0xbd, 0x2c, 0, 1])
    apdu = bytes([0x68, 4 + len(asdu), 0, 0, 0, 0]) + asdu
    ip = bytes([0x45, 0, 0, 0, 0, 0, 0, 0, 64, 6, 0, 0, 192, 0, 2, 10, 198, 51, 100, 10])
    pkt = bytes(12) + b'\x08\x00' + ip + bytes(12) + bytes([0x50]) + bytes(7) + apdu
    pcap = b'\xd4\xc3\xb2\xa1' + bytes(20) + struct.pack('<IIII', 0, 0, len(pkt), len(pkt)) + pkt
    cmd, _ = parse_pcap(pcap)
    assert (cmd['ioa'], cmd['qualifier'], cmd['src']) == (0x2cbd, 'ON', '192.0.2.10'), cmd


if __name__ == '__main__':
    demo()
    if not BASE:
        sys.exit('usage: python -I solve.py http://HOST:PORT')

    roster = get('/files/roster.json')['employees']
    events = get('/events')['signalling_events']
    rogue = {e['msisdn'] for e in events if int(e['gt'].split('-')[1]) > 999}
    targets = [e for e in roster if e['msisdn'] in rogue and e['ot_vpn_access']]
    assert len(targets) == 1, targets                         # ponytail: add /query/subscriber tiebreak if >1
    emp = targets[0]['employee_id']
    print('target :', emp, targets[0]['name'])

    print('confirm:', post('/confirm-target', {'employee_id': emp}))
    session = next(s for s in get('/query/vpn-window')['vpn_sessions'] if s['employee_id'] == emp)
    print('vpn    :', session['session_id'], 'from', session['source_ip'], 'at', session['start_time_utc'])

    cmd, live = parse_pcap(get('/files/iec104_capture.pcap', raw=True))
    print('command:', cmd)
    frozen = frozen_value(get('/files/hmi_monitoring.log', raw=True).decode(), cmd['ioa'], live)
    print('frozen :', frozen)

    report = {
        'ioa_address': hex(cmd['ioa']),
        'command_qualifier': cmd['qualifier'],
        'command_time_utc': cmd['time'].strftime('%H:%M'),
        'telemetry_status': f'{frozen:.1f}',
        'vpn_session_id': session['session_id'],
    }
    print('report :', report)
    print('result :', post('/submit', report))
