#!/usr/bin/env python3
"""polyglot-requiem: static analysis only. Nothing from the evidence is executed or contacted.
usage: python3 solve.py <path to flight-telemetry-sdk>"""
import sys,subprocess,struct,zipfile,io,hashlib,tempfile,sqlite3,os
R=sys.argv[1] if len(sys.argv)>1 else 'flight-telemetry-sdk'
g=lambda *a:subprocess.run(['git','-c','core.hooksPath=/dev/null','-C',R,*a],capture_output=True,text=True).stdout
print("== reachable history =="); print(g('log','--all','--format=%h %ad %s','--date=iso'))
print("== unreachable objects (git fsck) =="); print(subprocess.run(['git','-C',R,'fsck','--lost-found','--unreachable'],capture_output=True,text=True).stdout)
print("== unreachable commit c435f88 (shown as data, never run) =="); print(g('show','c435f88','--format=%h %an %ad%n%s','--date=iso','--','build.sh'))
epoch=int(g('show','-s','--format=%ct','c435f88').strip()); print("commit epoch (%ct) =",epoch,"\n")
png=open(os.path.join(R,'assets/telemetry_icon.png'),'rb').read()
print("== PNG chunks of assets/telemetry_icon.png ==")
p=8;tag=None
while p<len(png):
    l=struct.unpack('>I',png[p:p+4])[0];t=png[p+4:p+8]
    print(f"  {t!r:10} len={l}",png[p+8:p+8+l] if t==b'tEXt' else '')
    if t==b'tEXt' and png[p+8:p+8+11]==b'Provenance\0': tag=png[p+19:p+8+l].decode()
    p+=12+l
    if t==b'IEND':break
trailer=png[p:];print(f"  trailing bytes after IEND: {len(trailer)}  magic={trailer[:4]!r}  provenance tag={tag}\n")
z=zipfile.ZipFile(io.BytesIO(trailer));print("== embedded ZIP =="); [print("  ",i.filename,i.file_size) for i in z.infolist()]
dbb=z.read('telemetry_cache.db')
tf=tempfile.NamedTemporaryFile(suffix='.db',delete=False);tf.write(dbb);tf.close()
c=sqlite3.connect(tf.name)
print("\n== live rows in telemetry_cache.db =="); 
for n, in c.execute("select name from sqlite_master where type='table'"):
    for r in c.execute(f'select * from {n}'): print("  ",n,tuple(x.rstrip(bytes(1)) if isinstance(x,bytes) else x for x in r))
i=dbb.index(b'ci_provenance_seal'); blob=dbb[i+18:i+18+36]
print("\n== deleted (unlinked) cell found in raw page bytes ==\n  label:",dbb[i:i+18],"\n  36-byte blob:",blob.hex())
print("\n== static reading of assetsignd (disassembly): key = SHA256(reverse(tag_bytes) || epoch_u64_LE); out[i]=in[i]^key[i%32] ==")
key=hashlib.sha256(bytes.fromhex(tag)[::-1]+struct.pack('<Q',epoch)).digest()
pt=bytes(b^key[k%32] for k,b in enumerate(blob))
print("key =",key.hex()); print("FLAG:",pt.decode())
