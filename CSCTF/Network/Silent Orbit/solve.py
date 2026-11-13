import struct
d=open('civil_downlink.bin','rb').read()
pk=[];i=0
while i<len(d):
    assert i+6<=len(d),"trunc"
    w0,sq,ln=struct.unpack('>HHH',d[i:i+6]); n=ln+1
    assert i+6+n<=len(d),"trunc"
    pk.append((w0,sq,d[i+6:i+6+n])); i+=6+n
print(len(pk),"packets")
state='WAIT';size=None;cov=[];snap=None
def merge(iv):
    o=[]
    for a,b in sorted(iv):
        if o and a<=o[-1][1]: o[-1][1]=max(o[-1][1],b)
        else: o.append([a,b])
    return o
for w0,sq,u in pk:
    if (w0>>13)!=0 or (w0>>12)&1 or (w0>>11)&1 or (w0&0x7ff)!=0x321 or (sq>>14)!=3: continue
    if len(u)<4: continue
    b0=u[0]; L=(u[1]<<8)|u[2]; b3=u[3]
    if 7+L!=len(u): continue
    if b0>>5!=1 or (b0>>3)&1 or (b0>>2)&1 or (b0>>1)&1 or b0&1: continue
    if (b3>>4)&7!=0 or b3&7!=0: continue
    if len(u)<7 or tuple(u[4:7])!=(1,7,2): continue
    isdata=(b0>>4)&1; body=u[7:]
    if isdata:
        if b3&0x80 or b3&8: continue
        if state!='COLLECT' or len(body)<4: continue
        off=struct.unpack('>I',body[:4])[0]; pl=len(body)-4
        if off+pl<=size and pl>0: cov.append((off,off+pl))   # zero-length: no coverage
    else:
        if not body: continue
        dc=body[0]
        if dc==7:
            if state!='WAIT': continue
            if len(body)==8 and body[1]==0x0f and body[6]==0 and body[7]==0:
                size=struct.unpack('>I',body[2:6])[0]; state='COLLECT'; print("meta size",size)
        elif dc==4:
            if state!='COLLECT' or snap is not None: continue
            if len(body)==10 and body[1]==0 and body[2:6]==b'\0\0\0\0' and struct.unpack('>I',body[6:10])[0]==size:
                snap=merge(cov); print("eof accepted"); 
print("cov",snap)
E=size; miss=[];p=0
for a,b in snap:
    if a>p: miss.append((p,a))
    p=max(p,b)
if p<E: miss.append((p,E))
print("miss",miss)
data=bytes([7])+struct.pack('>II',0,E)+b''.join(struct.pack('>II',a,b) for a,b in miss)
pdu=bytes([0x28])+struct.pack('>H',len(data))+bytes([0,1,7,2])
pdu=bytes([0x28])+struct.pack('>H',len(data))+bytes([0,1,7,2])+bytes([8])+data[1:]
print(pdu.hex().upper()); print("CSCTF{"+pdu.hex().upper()+"}")
