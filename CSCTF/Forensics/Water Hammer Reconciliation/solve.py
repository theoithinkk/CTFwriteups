#!/usr/bin/env python3
"""water-hammer-reconciliation: Modbus/TCP matched-readback reconstruction.
usage: python3 solve.py reserve-header.pcapng   (pure stdlib; capture is only parsed, never replayed)"""
import struct,sys,hashlib,base64
f=sys.argv[1] if len(sys.argv)>1 else 'reserve-header.pcapng'
d=open(f,'rb').read();p=0;pk=[]
while p<len(d):                               # pcapng: Enhanced Packet Blocks (type 6)
    t,l=struct.unpack('<II',d[p:p+8])
    if t==6: cl=struct.unpack('<I',d[p+20:p+24])[0];pk.append(d[p+28:p+28+cl])
    p+=l
flows={}
for i,fr in enumerate(pk):
    if fr[12:14]!=b'\x08\x00':continue
    ip=fr[14:];ihl=(ip[0]&15)*4;tl=struct.unpack('>H',ip[2:4])[0];tcp=ip[ihl:tl]
    sp,dp,seq=struct.unpack('>HHI',tcp[:8]);off=(tcp[12]>>4)*4
    flows.setdefault((sp,dp),[]).append((i,seq,tcp[13],tcp[off:]))
print(f"packets={len(pk)}  tcp flows={[(k,len(v)) for k,v in flows.items()]}")
def reasm(v):                                 # byte-exact TCP reassembly, de-duplicating retransmits
    isn=[s for _,s,fl,_ in v if fl&2][0]+1;data={}
    for i,s,fl,pay in v:
        for j,b in enumerate(pay): data.setdefault(s+j-isn,(b,i))
    n=max(data)+1;assert all(o in data for o in range(n))
    return bytes(data[o][0] for o in range(n)),[data[o][1] for o in range(n)]
(cs,ci),(ss,si)=[reasm(flows[k]) for k in ((36853,502),(502,36853))]
def adus(s,ix,dn):
    r=[];p=0
    while p<len(s):
        tid,pid,L=struct.unpack('>HHH',s[p:p+6]);a=s[p:p+6+L]
        r.append(dict(d=dn,tid=tid,L=L,raw=a,end=ix[p+len(a)-1],ok=len(a)==6+L and pid==0));p+=6+L
    return r
ev=sorted(adus(cs,ci,'C')+adus(ss,si,'S'),key=lambda e:e['end']);n=len(ev)
print(f"reassembled ADUs: {sum(e['d']=='C' for e in ev)} requests, {sum(e['d']=='S' for e in ev)} responses (all well-formed: {all(e['ok'] for e in ev)})")
rows=[];used=set();dec={'exception':[],'unanswered':[]}
for i,e in enumerate(ev):
    r=e['raw']
    if e['d']!='C' or len(r)<13 or r[6]!=17 or r[7]!=0x10:continue
    A,N=struct.unpack('>HH',r[8:12])
    if not(1<=N<=4 and A>=0x1000 and A+N-1<=0x1003 and e['L']==7+2*N and r[12]==2*N and len(r)==13+2*N):continue
    S=[j for j in range(n) if ev[j]['d']=='S' and ev[j]['tid']==e['tid']]
    if not S:dec['unanswered'].append(e['tid']);continue
    s=ev[S[0]]
    if len(S)!=1 or s['raw'][7]&0x80:dec['exception'].append(e['tid']);continue
    if not(s['L']==6 and s['raw'][6:12]==bytes([17,0x10])+r[8:12]):continue
    k=next((k for k in range(S[0]+1,n) if ev[k]['d']=='C'),None)       # immediately next client ADU
    if k is None:continue
    q=ev[k]
    if q['L']!=6 or q['raw'][6:]!=bytes.fromhex('110310000004'):continue
    m=[x for x in range(n) if ev[x]['d']=='S' and ev[x]['tid']==q['tid']]
    if len(m)!=1 or m[0]<k or q['tid'] in used:continue
    fr=ev[m[0]]
    if not(fr['L']==11 and fr['raw'][6:9]==bytes([17,3,8])):continue
    used.add(q['tid']);rows.append((S[0],s['tid'],struct.unpack('>4H',fr['raw'][9:17])))
print(f"decoys discarded: FC16 exception tid={dec['exception']}, unanswered FC16 tid={dec['unanswered']}")
print(f"confirmed snapshots: {len(rows)}")
def V(p,g):return (p*g//1000)*1000000//70686
T=2*20000*1000000//1065000;prev=V(80,500);mask=0;lines=[]
for i,(_,tid,(p,g,a,r)) in enumerate(sorted(rows)):
    v=V(p,g);Q=998*1065*abs(v-prev);u=int(a==1 and r<T and Q>9000*100000)
    mask|=u<<(63-i);prev=v;lines.append(f"i={i};tid={tid:04X};p={p};g={g};a={a};r={r}")
    if i<3 or i>60:print(f"  row {i:>2} tid={tid:04X} P={p} G={g} A={a} R={r}  V={v} Q={Q} UNSAFE={u}")
def report(init,rowlines,mask):return "water-hammer-reconciliation-v2\ninitial;p=%d;g=%d;a=%d;r=%d\nn=%d\n"%(*init,len(rowlines))+"\n".join(rowlines)+"\nunsafe-mask=%016X"%mask
def flag(R):return base64.b32encode(hashlib.sha256(R.encode()).digest()[:24]).decode().rstrip('=')
# self-check against the profile's public synthetic vector
tv=report((80,500,0,60000),["i=0;tid=0101;p=160;g=1000;a=1;r=5000","i=1;tid=0102;p=160;g=1000;a=0;r=60000"],1<<63)
print("test vector Base32:",flag(tv),"(expected IAO7QJHG2XIJQ5I2PR7OA6WYEEPRHF7OO6M6QOA)")
R=report((80,500,0,60000),lines,mask);print("T_US =",T,"  unsafe-mask =",'%016X'%mask)
print("SHA-256(R) =",hashlib.sha256(R.encode()).hexdigest());print("FLAG: CSCTF{%s}"%flag(R))
