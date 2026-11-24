Flag: CSCTF{layer_remembers_93e33478c}
Category: Forensics (OCI layer whiteout recovery)
Tools used: unzip, Python (json, tarfile, gzip, hmac, hashlib)
Challenge: The Layer That Wouldn't Die (CSCTF 2026, Forensics, Easy, 120 pts, author: Mohamed Amine Mzoughi)

Steps:

1. Start point: the handout's OCI image layout
   - What I did: unzipped the handout archive (its SHA-256 matched the one in the brief) and read oci-layout, index.json and the blob directory.
   - What I found: a single image, cascade-historian-config:site-east, with a manifest, a config blob and five layer blobs.
   - Thinking: the brief says the marker that opens the seal is gone from the final filesystem, so the answer should be in the layer history, not the merged filesystem.

2. Pivot: the config history describes the seal
   - What I did: read the config blob's labels and history.
   - What I found: the COPY historian.key.sealed step carries a comment describing the seal: sealed = plaintext XOR repeating(HMAC-SHA256(key = bytes.fromhex(Labels["build.seal"]), msg = raw bytes of /etc/cascade/.sealed_marker "as it stands at the end of this layer")). The label key is ddc9bfb15738fbd10757eb936a593931. The history also shows COPY site-rev-b/ and rm -f /etc/cascade/.sealed_marker pushed later by a different author.
   - Thinking: "as it stands at the end of this layer" is the catch. The marker may have changed after the seal was made, so I need its value at that exact layer.

3. Pivot: every layer read as data
   - What I did: decompressed each layer tarball in memory and listed members with their contents.
   - What I found: layer 2 creates .sealed_marker = f4901a8d069d99180eed0cb14c8fd2a9 (rev A). Layer 3 adds historian.key.sealed (32 bytes). Layer 4 overwrites the marker with f5d8040f988f7e4917c0281af23d00ac (rev B). Layer 5 deletes it with a whiteout, .wh..sealed_marker.
   - Thinking: at the end of layer 3 the marker was still rev A. Rev B is a decoy because it was written after the seal, and the whiteout in layer 5 explains why the file looks gone.

4. Flag: unseal with the rev-A marker
   - What I did: computed HMAC-SHA256 with the label key over each marker version and XORed the repeated 32-byte digest against the 32-byte sealed file.
   - What I found: rev B gives unreadable bytes; rev A gives printable text starting with CSCTF{.
   - Thinking: printable output in the flag format confirms rev A is the marker version the seal was made with.
   - Result: CSCTF{layer_remembers_93e33478c}

Key insight: The seal was keyed on the marker as it stood at the end of layer 3, so the rev-A value still stored in layer 2 unseals it, while the later rev-B overwrite and the layer-5 whiteout are decoys. A file deleted in a later layer is still stored in the layer that created it.
Defensive takeaways: An rm in a later image layer only adds a whiteout; the file stays in the layer that created it, and here the seal key also shipped in an image label. Treat anything that ever landed in a layer or label as published, keep secrets out of image builds, and rotate any that leaked.
Note: nothing from the image was executed; all layers were read as data. There is no solve.py or reproduction capture because the challenge input files are not in this repo.
