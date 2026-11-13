#!/usr/bin/env python3
"""recon-plate: two gzip+tar messages hidden in bit-planes 0 and 1 of the first pixel rows.
usage: python3 solve.py recon-plate.png"""
import sys,struct,zlib,tarfile,io
import numpy as np
from PIL import Image
a=np.array(Image.open(sys.argv[1]).convert('RGB')).reshape(-1)
low=a&3
nz=np.nonzero(low)[0]
print(f"samples (R,G,B bytes in raster order): {a.size}; samples with non-zero low 2 bits: {len(nz)}; last one at sample index {nz.max()} (= pixel row {nz.max()//768})")
print("low 2 bits are zero everywhere else -> the image was quantised to multiples of 4 and the payload lives in bits 0 and 1\n")
for name,bits in (('bit 0 plane',low&1),('bit 1 plane',low>>1)):
    by=bytes(np.packbits(bits[:2400].astype(np.uint8)))
    L=struct.unpack('>I',by[:4])[0]; gz=by[4:4+L]
    print(f"== {name}: big-endian length prefix = {L}, gzip magic = {gz[:2].hex()}")
    tar=tarfile.open(fileobj=io.BytesIO(zlib.decompress(gz,31)))
    for m in tar: print(f"   {m.name:<22} {tar.extractfile(m).read().decode().rstrip()!r}")
