Challenge: Redline, Forensics / Easy / 120 pts / author: Chronos Security (CSCTF 2026)
Flag: CSCTF{redline_21ee9b19d342e06432165fb2b6f64e06}
Category: Forensics (DOCX tracked-change recovery)
Tools used: Python 3 (stdlib zipfile + regex), solve.py

Brief: during a grid-instability night a cold-chain excursion directive (CC-11, Depot 7) went out to depot crews. A
crew lead kept their copy, and it "reads wrong." The directive is a .docx. Work out how the copy that reached the
crews differs from what was approved, who changed it, and recover the original excursion authorization.

Steps:
1. Start point: a .docx is a ZIP of XML. Unzip it and read the parts.
   - What I found: docProps/core.xml names the original author as "A. Reyes" (dc:creator) but
     cp:lastModifiedBy = "s.kessler", with cp:revision 4. So someone other than the author touched the file last.
   - Thinking: a directive that "reads wrong" plus a different last editor points straight at tracked changes
     (Word revisions), which Word stores inline in word/document.xml as <w:ins> (insertions) and <w:del> (deletions),
     each stamped with w:author and w:date.

2. Pivot: pull every tracked insertion and deletion.
   - What I found: all nine revisions are by s.kessler, stamped 2026-10-07T02:41Z. The deletions and insertions are a
     matched rewrite of the directive's meaning:
       deleted "temperature" -> inserted "thermal"; deleted "30" -> inserted "90" (loosening the excursion limit);
       deleted  "Vials that exceeded 8 C MUST be quarantined and MUST NOT be redistributed."
       inserted "Vials that exceeded 8 C may be returned to distribution at depot-supervisor discretion."
     word/comments.xml has s.kessler's note: "I am dropping the quarantine hold ... Re-issuing under a fresh
     authorization." So the safety hold was deliberately reversed.
   - Thinking: the authorization token was part of that rewrite. The DELETED authorization is the original approved
     one; the INSERTED authorization is the forgery kessler substituted.

3. Pivot: separate the real authorization from the forged one.
   - What I found: deleted (original) authorization = CSCTF{redline_21ee9b19d342e06432165fb2b6f64e06}
     (split across two deletion runs in the XML, which I rejoin). Inserted (forged) authorization =
     CSCTF{dispatch_0f7c0c00aac69bbb86d6b96391f5d112}, the decoy that went out to the crews.
   - Result: the original excursion authorization is the deleted token.

Flag: CSCTF{redline_21ee9b19d342e06432165fb2b6f64e06}

Reproduce: python3 solve.py CC-11_excursion_directive.docx
Key insight: Word keeps deleted text inside document.xml as w:del runs, so the approved authorization was never gone, just marked deleted, while a forged one was inserted in its place by s.kessler.

Defensive takeaways: Distributing a .docx without flattening it leaves the full edit history, authors and timestamps embedded. For forensics that is a gift, but for anyone publishing a document it is a leak, so export to PDF or run Document Inspector before release. Safety-critical directives should also be signed or hashed at approval time, so a later unapproved rewrite (here: quarantine to redistribute, by a non-author) is detectable instead of silently shipping to crews.

Note: the screenshot is a live re-run of solve.py against the challenge's own .docx; it reproduces the documented flag.
