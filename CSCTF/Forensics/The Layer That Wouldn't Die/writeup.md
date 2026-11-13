Challenge: The Layer That Wouldn't Die, Forensics / Easy / 120 pts / author: Mohamed Amine Mzoughi (CSCTF 2026)
Flag: CSCTF{layer_remembers_93e33478c}
Category: Forensics (OCI layer whiteout recovery)
Tools used: unzip, Python (json, tarfile, gzip, hmac, hashlib). Nothing from the image was executed; all layers were read as data.

Steps:
1. Start point: inspect the OCI layout
   - What I did / What I found: Unzipped the archive (SHA-256 matched the one in the brief) and read oci-layout, index.json and the blob directory.
   - Result: A single image, cascade-historian-config:site-east, with a manifest, a config blob and five layer blobs.
   - Thinking: The brief says the marker that opens the seal is gone from the final filesystem, so the answer should be in the layer history, not the merged filesystem.

_(No reproduction capture: the challenge input files are not in this repo.)_

2. Pivot: read the config history for the seal rule
   - What I did / What I found: Read the config blob: labels and history. The COPY historian.key.sealed step carries a comment describing how the seal was made.
   - Result: sealed = plaintext XOR repeating(HMAC-SHA256(key = bytes.fromhex(Labels["build.seal"]), msg = raw bytes of /etc/cascade/.sealed_marker as it stands at the end of that layer)). The key is ddc9bfb15738fbd10757eb936a593931. The history also shows COPY site-rev-b/ and rm -f /etc/cascade/.sealed_marker pushed later by a different author.
   - Thinking: The wording "as it stands at the end of this layer" is the catch. The marker may have changed after the seal was made.


3. Pivot: read every layer as data
   - What I did / What I found: Decompressed each layer tarball in memory and listed members with their contents.
   - Result: Layer 2 creates .sealed_marker = f4901a8d069d99180eed0cb14c8fd2a9 (rev A). Layer 3 adds historian.key.sealed (32 bytes). Layer 4 overwrites the marker with f5d8040f988f7e4917c0281af23d00ac (rev B). Layer 5 deletes it with a whiteout, .wh..sealed_marker.
   - Thinking: At the end of layer 3 the marker was still rev A. Rev B, the value in layer 4, is a decoy because it was written after the seal, and the whiteout in layer 5 explains why the file looks gone.


4. Result: unseal with the correct marker version
   - What I did / What I found: Computed the HMAC-SHA256 with the label key over each marker version and XORed the repeated 32-byte digest against the 32-byte sealed file.
   - Result: Rev A gives CSCTF{layer_remembers_93e33478c}. Rev B gives unreadable bytes.
   - Thinking: Printable output starting with CSCTF{ confirms the right marker version.


Key insight: A file deleted in a later layer is still stored in the layer that created it. The seal depends on the marker as of layer 3, so the rev-A marker from layer 2 is what unlocks it. The rev-B overwrite is a decoy, and the layer 5 whiteout only hides the file from the merged view.
