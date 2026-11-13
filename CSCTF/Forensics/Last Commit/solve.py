#!/usr/bin/env python3
"""last-commit: rebuild the registry at the moment LR-731 became COMPLETED.
usage: python3 solve.py <dir with registry.sqlite, registry.sqlite-wal, delivery.csv>
Works on in-memory copies only; the evidence pair is never opened by SQLite."""
import struct,sqlite3,csv,hashlib,sys,os
D=sys.argv[1] if len(sys.argv)>1 else '.'
w=open(os.path.join(D,'registry.sqlite-wal'),'rb').read()
db=open(os.path.join(D,'registry.sqlite'),'rb').read()
magic,ver,ps,seq,s1,s2,c1,c2=struct.unpack('>8I',w[:32])
be=magic&1
def ck(data,a,b):
    v=struct.unpack(('>' if be else '<')+'%dI'%(len(data)//4),data)
    for i in range(0,len(v),2):
        a=(a+v[i]+b)&0xffffffff; b=(b+v[i+1]+a)&0xffffffff
    return a,b
a,b=ck(w[:24],0,0)
print(f"WAL header: magic={magic:#x} page_size={ps} salts={s1:#x},{s2:#x} header_checksum_ok={(a,b)==(c1,c2)}")
frames=[];off=32
print("\nframe  page  dbsize(commit)  salt_ok  checksum_ok")
while off+24+ps<=len(w):
    pg,sz,f1,f2,k1,k2=struct.unpack('>6I',w[off:off+24]);data=w[off+24:off+24+ps]
    ok=(f1==s1 and f2==s2)
    if ok:
        a,b=ck(w[off:off+8],a,b);a,b=ck(data,a,b);ok=(a,b)==(k1,k2)
    print(f"{len(frames):>5}  {pg:>4}  {sz:>14}  {str(f1==s1 and f2==s2):>7}  {ok}")
    if not ok:break
    frames.append((pg,sz,data));off+=24+ps
pages={i+1:db[i*ps:(i+1)*ps] for i in range(len(db)//ps)}
pend={};states={}
for i,(pg,sz,d) in enumerate(frames):
    pend[pg]=d
    if sz:
        pages.update(pend);pend={}
        states[i]=b''.join(pages.get(k,b'\0'*ps) for k in range(1,sz+1))
rows=list(csv.reader(open(os.path.join(D,'delivery.csv'))))[1:]
print("\ncommit frames -> export_job state of LR-731, and export SHA-256")
for i,img in states.items():
    import tempfile;tf=tempfile.NamedTemporaryFile(suffix='.sqlite',delete=False);tf.write(img);tf.close();c=sqlite3.connect(tf.name)
    job=c.execute("select state from export_job where job_id='LR-731'").fetchall()
    c.execute("create temp table manifest(job_id TEXT, position INTEGER, parcel_id INTEGER)")
    c.executemany("insert into manifest values(?,?,?)",[(x,int(y),int(z)) for x,y,z in rows])
    q=c.execute("""SELECT m.position,p.parcel_id,p.district,p.plot_ref,h.registry_ref,t.interest_bps,t.instrument_ref
FROM manifest AS m JOIN parcel AS p ON p.parcel_id=m.parcel_id
JOIN title AS t ON t.parcel_id=p.parcel_id JOIN holder AS h ON h.holder_id=t.holder_id
WHERE m.job_id='LR-731' ORDER BY m.position ASC,h.registry_ref COLLATE BINARY ASC;""").fetchall()
    out="position\tparcel_id\tdistrict\tplot_ref\tregistry_ref\tinterest_bps\tinstrument_ref\n"+"".join("\t".join(map(str,r))+"\n" for r in q)
    h=hashlib.sha256(out.encode()).hexdigest()
    print(f"frame {i}: job={job[0][0] if job else '-':<10} rows={len(q):>2}  sha256={h}")
    states[i]=(job[0][0] if job else None,h)
first=min(i for i,(j,h) in states.items() if j=='COMPLETED')
print(f"\nFirst commit where LR-731 == COMPLETED: frame {first}")
print(f"FLAG: CSCTF{{last_commit_{states[first][1]}}}")
