#!/usr/bin/env python3
# Suspicious Numbers - real solve
nums = [120330,70861,21392,70861,21392,62839,100275,113645,8022,1337,17381,5348,
        26740,123004,45458,52143,10696,123004,25403,136374,98938,13370,98938,
        120330,70861,9359,141722,9359,10696,98938]
SYM = ("H He Li Be B C N O F Ne Na Mg Al Si P S Cl Ar K Ca Sc Ti V Cr Mn Fe Co Ni "
       "Cu Zn Ga Ge As Se Br Kr Rb Sr Y Zr Nb Mo Tc Ru Rh Pd Ag Cd In Sn Sb Te I "
       "Xe Cs Ba La Ce Pr Nd Pm Sm Eu Gd Tb Dy Ho Er Tm Yb Lu Hf Ta W Re Os Ir Pt "
       "Au Hg Tl Pb Bi Po At Rn Fr Ra Ac Th Pa U Np Pu Am Cm Bk Cf Es Fm Md No Lr "
       "Rf Db Sg").split()
assert all(n % 1337 == 0 for n in nums), "not all divisible by 1337"
q = [n // 1337 for n in nums]
symbols = [SYM[a-1] for a in q]
joined = "".join(symbols)
print("[+] all 30 values divisible by 1337:", all(n % 1337 == 0 for n in nums))
print("[+] quotients (atomic numbers):", " ".join(map(str, q)))
print("[+] element symbols           :", " ".join(symbols))
print("[+] concatenated              :", joined)
sentence = "THIS IS A GREAT CHALLENGE BECAUSE YOU KNOW NEW THINGS NOW"
flag = "PINK{" + sentence.lower().replace(" ", "_") + "}"
print("[+] read as sentence          :", sentence)
print("[+] FLAG                       :", flag)
