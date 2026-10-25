Status: IN PROGRESS. Rejected by the site: PacketCapture{-85.60, -81.09}
Category: OSINT
Tools used: curl, Python (Pillow), TinEye, steghide (Docker), what3words
Steps:
1. Downloaded treasurehunttrip.jpg from MediaFire. Its JPEG comment says "you've searched yourself into a wrong hole", a decoy telling you to stop digging in metadata.
2. TinEye matched a Shutterstock stock photo. The WorldAtlas 1300px copy is pixel-identical, so nothing is hidden in the image (steghide and bit planes were also empty).
3. "3 words would suffice" = what3words. The file name splits into three words: ///treasure.hunt.trip.
4. what3words resolves it to -85.600191, -81.091278 (Antarctica), which is -85.60, -81.09 at two decimals.
Key insight: The clue was the file name, not the file. Ruling out stego quickly (diffing against the original stock photo) pointed back to the hint in the brief.

Also ruled out: the other word orders (Antarctica/ocean), object-based triples (chest/map/compass...), steghide with ~25 passwords, and the MediaFire description (empty).
