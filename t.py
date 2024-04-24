from rfc7748 import x25519, add, computeVcoordinate, mult
from Crypto.Hash import SHA256
from random import randint
from algebra import mod_inv

p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

BaseU = 9
BaseV = computeVcoordinate(BaseU)


def H(message):
    h = SHA256.new(message)
    return (int(h.hexdigest(), 16))

def ECDSA_generate_nonce():

    return randint(1, ORDER - 1)


def ECDSA_generate_keys(priv_key):

    return priv_key, mult(priv_key, BaseU, BaseV, p)


def ECDSA_sign(priv_key, m, k):

    z = H(m)
    x1, y1 = mult(k, BaseU, BaseV, p)
    r = x1 % ORDER
    s = (z + r * priv_key) * mod_inv(k, ORDER) % ORDER
    return r, s


def ECDSA_verify(pub_key, m, r, s):

    if not (0 < r < ORDER and 0 < s < ORDER):
        return False

    z = H(m)
    w = mod_inv(s, ORDER)
    u1 = z * w % ORDER
    u2 = r * w % ORDER

    x1, y1 = mult(u1, BaseU, BaseV, p)
    x2, y2 = mult(u2, *pub_key, p)
    x, y = add(x1, y1, x2, y2, p)

    return x % ORDER == r

#       TEST        #
m = b"A very very important message !"
x = 0xc841f4896fe86c971bedbcf114a6cfd97e4454c9be9aba876d5a195995e2ba8
k = 0x2c92639dcf417afeae31e0f8fddc8e48b3e11d840523f54aaa97174221faee6

priv_key = x
priv_key1, pub_key = ECDSA_generate_keys(priv_key)

r_gen, s_gen = ECDSA_sign(priv_key, m, k)

is_valid = ECDSA_verify(pub_key, m, r_gen, s_gen)

r = 0x429146a1375614034c65c2b6a86b2fc4aec00147f223cb2a7a22272d4a3fdd2
s = 0xf23bcdebe2e0d8571d195a9b8a05364b14944032032eeeecd22a0f6e94f8f33

if is_valid:
    print("VALID")
else:
    print("INVALID")