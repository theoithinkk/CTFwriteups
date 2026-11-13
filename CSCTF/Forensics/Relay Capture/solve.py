#!/usr/bin/env python3
"""relay-capture: recover the cropped-away rows from data left after IEND (acropalypse-style).
usage: python3 solve.py relay-capture.png [out.png]"""
import sys,struct,zlib,re
from PIL import Image
src=sys.argv[1];dst=sys.argv[2] if len(sys.argv)>2 else 'recovered.png'
d=open(src,'rb').read()
iend=d.index(b'IEND')+8
tail=d[iend:]
print(f"file size {len(d)} bytes; visible PNG ends at {iend}; trailing bytes after IEND: {len(tail)}")
ih=struct.unpack('>II',d[16:24]);print("visible image size:",ih)
idat=[m.start() for m in re.finditer(b'IDAT',tail)]
print("stale IDAT chunk headers inside trailer at offsets:",idat[:4],"...",f"({len(idat)} total, spacing {idat[1]-idat[0]})")
# rebuild one raw deflate stream: leading partial chunk body + each later chunk body (drop length/type/crc)
first=idat[0]-4
s=bytearray(tail[:first]);p=first
while tail[p+4:p+8]==b'IDAT':
    l=struct.unpack('>I',tail[p:p+4])[0];s+=tail[p+8:p+8+l];p+=12+l
s=bytes(s);print(f"reassembled deflate bytes: {len(s)}")
# the stream starts mid-block: try every bit offset, raw-inflate with a 32 KiB zero dictionary
big=int.from_bytes(s,'little');n=len(s);best=(0,None,None)
for k in range(n*8-40):
    o=zlib.decompressobj(-15,zdict=b'\0'*32768)
    try: out=o.decompress((big>>k).to_bytes(n,'little'))
    except zlib.error: continue
    if len(out)>best[0]: best=(len(out),k,out)
L,k,out=best
W=520;stride=W*3+1
print(f"best bit offset = {k}: inflated {L} bytes = {L//stride} rows x {W} px (remainder {L%stride}); filter types used: {sorted(set(out[i*stride] for i in range(L//stride)))}")
rows=L//stride;prev=bytearray(W*3);img=[]
for r in range(rows):
    f=out[r*stride];line=bytearray(out[r*stride+1:(r+1)*stride])
    for i in range(len(line)):
        a=line[i-3] if i>=3 else 0;b=prev[i];c=prev[i-3] if i>=3 else 0
        if f==1:line[i]=(line[i]+a)&255
        elif f==2:line[i]=(line[i]+b)&255
        elif f==3:line[i]=(line[i]+(a+b)//2)&255
        elif f==4:
            pp=a+b-c;pa,pb,pc=abs(pp-a),abs(pp-b),abs(pp-c);pr=a if pa<=pb and pa<=pc else (b if pb<=pc else c);line[i]=(line[i]+pr)&255
    prev=line;img.append(bytes(line))
Image.frombytes('RGB',(W,rows),b''.join(img)).save(dst);print("wrote",dst,"-> read the key line from the image")
