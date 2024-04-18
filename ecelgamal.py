from rfc7748 import x25519, add, sub, computeVcoordinate, mult
from random import randint
from algebra import mod_inv


p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

BaseU = 9
BaseV = computeVcoordinate(BaseU)

def bruteECLog(C1, C2, p):
    s1, s2 = 1, 0
    for i in range(p):
        if s1 == C1 and s2 == C2:
            return i
        s1, s2 = add(s1, s2, BaseU, BaseV, p)
    return -1

def EGencode(message):
    if message == 0:
        return (1,0)
    if message == 1:
        return (BaseU, BaseV)

def ECEG_generate_keys():
    private_key = randint(1, ORDER-1)
    public_key = mult(private_key, BaseU, BaseV, p)
    return private_key, public_key

def ECEG_encrypt(message, public_key):
    r = randint(1, ORDER-1)
    R = mult(r, BaseU, BaseV, p)
    shared_secret = mult(r, public_key[0], public_key[1], p)
    S = add(shared_secret[0], shared_secret[1], EGencode(message)[0], EGencode(message)[1], p)
    return R, S

def ECEG_decrypt(private_key, r, s):
    shared_secret = mult(private_key, r[0], r[1], p)
    inv_shared_secret = (shared_secret[0], -shared_secret[1] % p)
    message_point = sub(s[0], s[1], inv_shared_secret[0], inv_shared_secret[1], p)
    return bruteECLog(message_point[0], message_point[1], p)
