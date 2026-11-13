#!/usr/bin/env python3
"""Redline: recover the original cold-chain excursion authorization that was
deleted with tracked changes from a .docx, and name who changed it.
usage: python3 solve.py CC-11_excursion_directive.docx
stdlib only (zipfile + regex over the WordprocessingML); the file is only read."""
import sys, re, zipfile

def text_of(inner):  # concatenate the run text inside a revision element
    return ''.join(re.findall(r'<w:(?:delText|t)[^>]*>(.*?)</w:(?:delText|t)>', inner, re.S))

def solve(path):
    z = zipfile.ZipFile(path)
    core = z.read('docProps/core.xml').decode('utf-8', 'replace')
    creator = re.search(r'<dc:creator>(.*?)</dc:creator>', core).group(1)
    editor = re.search(r'<cp:lastModifiedBy>(.*?)</cp:lastModifiedBy>', core).group(1)
    print(f"document author (creator): {creator}")
    print(f"last modified by         : {editor}\n")

    doc = z.read('word/document.xml').decode('utf-8', 'replace')
    ins, dele = [], []
    for m in re.finditer(r'<w:(ins|del)\b[^>]*w:author="([^"]*)"[^>]*w:date="([^"]*)"[^>]*>(.*?)</w:\1>', doc, re.S):
        kind, author, date, inner = m.groups()
        (ins if kind == 'ins' else dele).append((author, date, text_of(inner)))

    for k, rows in (("INSERTED", ins), ("DELETED", dele)):
        print(f"-- {k} by tracked changes --")
        for author, date, t in rows:
            if t.strip():
                print(f"   {author} {date}: {t!r}")
        print()

    flag_re = re.compile(r'CSCTF\{[^}]*\}')
    # The approved original is the authorization that was DELETED; the INSERTED one is the forgery.
    deleted_flags = flag_re.findall(''.join(t for _, _, t in dele))
    inserted_flags = flag_re.findall(''.join(t for _, _, t in ins))
    flag = deleted_flags[0]
    print(f"forged (inserted) authorization : {inserted_flags[0] if inserted_flags else '-'}")
    print(f"changed by                      : {dele[0][0]}")
    print("FLAG (original, deleted authorization):", flag)
    return flag

if __name__ == "__main__":
    solve(sys.argv[1] if len(sys.argv) > 1 else "CC-11_excursion_directive.docx")
