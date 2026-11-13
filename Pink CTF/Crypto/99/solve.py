"""Solve "99" (Pink CTF, Crypto): QWERTZ-99 image + .qmap, salted with QWERTZ-98.

Usage: python solve.py secure.png pink.qmap
"""
import re
import sys

from PIL import Image

sys.set_int_max_str_digits(0)  # the salted number is ~620 digits


def image_to_digits(path):
    # Each pixel stores one symbol (0-9, or 11 for '-') hidden behind two random masks.
    # The "main" channel rotates with the pixel index: pos = idx % 4.
    img = Image.open(path).convert("RGBA")
    w, h = img.size
    px = img.load()
    out = []
    for idx in range(w * h):
        c = px[idx % w, idx // w]
        p = idx % 4
        a = (c[p] - c[(p + 1) % 4]) % 256            # (num + m1) - m1
        b = (c[(p + 3) % 4] - c[(p + 2) % 4]) % 256  # (num + m2) - m2
        if a == b and a <= 11:  # both copies agree -> real data, not padding
            out.append("-" if a == 11 else str(a))
    return "".join(out).rstrip("0")  # trailing 0s are padding pixels


def load_qmap(path):
    text = open(path).read()
    width = int(re.search(r"\{c:(\d+)\}", text).group(1))
    code_to_char = {code: chr(int(o)) for o, code in re.findall(r"\((\d+)\|(\d+)\)", text)}
    return width, code_to_char


def password_number(pw, char_to_code):
    # QWERTZ-98 key: int(concatenated codes) * product of each code
    p = int("".join(char_to_code[ch] for ch in pw))
    for ch in pw:
        p *= int(char_to_code[ch])
    return p


def decode(digits, width, code_to_char):
    assert digits.endswith("99"), "QWERTZ-99 strings end with the 99 terminator"
    body = digits[:-2]
    return "".join(code_to_char.get(body[i:i + width], "?") for i in range(0, len(body), width))


if __name__ == "__main__":
    salted = image_to_digits(sys.argv[1])
    width, table = load_qmap(sys.argv[2])
    char_to_code = {v: k for k, v in table.items()}
    assert salted.endswith("-98"), "image holds a QWERTZ-98 (password-salted) string"

    # ponytail: password recovered by factoring N (see writeup), hardcoded here
    N = int(salted[:-3])
    P = password_number("13371337", char_to_code)
    assert N % P == 0, "wrong password: P must divide N exactly"
    message = decode(str(N // P) + "99", width, table)
    print("layer 1:", message)

    inner = message.rsplit(" ", 1)[-1]  # trailing digits are a second QWERTZ-99 string
    flag = decode(inner, width, table)
    print("flag:   ", flag)
    assert flag == "PINK{NiNeTyNiNeQwErTzEs}"
