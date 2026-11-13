#!/usr/bin/env python3
"""last-buffer: parse both Vim swap files by hand (no vim needed) and pick the one from the shell that died.
usage: python3 solve.py <dir with the handout files>"""
import sys,os,struct,json,base64,hashlib
D=sys.argv[1] if len(sys.argv)>1 else '.'
ctx=json.load(open(os.path.join(D,'case-context.json')))
print("case window:",ctx['crash_window_start'],"->",ctx['crash_window_end'],"  target tty:",ctx['target_tty'])
print("\n-- shell journal / audit timeline --")
for fn in ('shell-journal.jsonl','audit-timeline.jsonl'):
    for l in open(os.path.join(D,fn)):
        j=json.loads(l);print(f"  {fn[:5]} {j.get('time')} {j.get('tty','')} pid={j.get('process_pid',j.get('pid',''))} {j.get('event')} {j.get('command',j.get('reason',j.get('signal',j.get('result',''))))}")
saved=hashlib.sha256(open(os.path.join(D,ctx['saved_file']),'rb').read()).hexdigest()
print("\nsha256 of saved incident-2026-10-07.md =",saved)
res={}
for fn in ('incident-2026-10-07.md.swp','incident-2026-10-07.md.swo'):
    d=open(os.path.join(D,fn),'rb').read()
    pid=struct.unpack('<I',d[24:28])[0];user=d[28:68].split(b'\0')[0].decode();path=d[108:300].split(b'\0')[0].decode()
    print(f"\n== {fn}: magic={d[:2]} page={struct.unpack('<I',d[12:16])[0]} pid={pid} user={user} path={path}")
    lines=[]
    for b in range(len(d)//4096):
        pg=d[b*4096:(b+1)*4096]
        if pg[:2]==b'ad':                      # data block, id 0x6461 little endian
            n=struct.unpack('<Q',pg[16:24])[0]
            for o in struct.unpack('<%dI'%n,pg[24:24+4*n]):lines.append(pg[o:pg.index(b'\0',o)].decode())
    for l in lines:print("   |",l)
    kv=dict(l.split(': ',1) for l in lines if ': ' in l)
    res[fn]=(pid,kv)
print("\n== decision ==")
for fn,(pid,kv) in res.items():
    print(f"  {fn}: pid {pid}, base_file_sha256 matches saved file: {kv.get('base_file_sha256')==saved}, status={kv.get('status')}, revision={kv.get('revision_id')}")
win=[fn for fn,(pid,kv) in res.items() if pid==8442][0]
b64=res[win][1]['authorization_b64'];print("\nchosen:",win,"-> authorization_b64 =",b64)
print("decoded:",base64.urlsafe_b64decode(b64+'='*(-len(b64)%4)).decode())
other=[fn for fn in res if fn!=win][0];b2=res[other][1]['authorization_b64']
print("decoy decodes to:",base64.urlsafe_b64decode(b2+'='*(-len(b2)%4)).decode())
