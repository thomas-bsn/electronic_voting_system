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
    return randint(1, ORDER-1)


def ECDSA_generate_keys(pkey):
    res = mult(pkey, BaseU, BaseV, p)
    return pkey, res


def ECDSA_sign(message, private_key, nonce):
    z = H(message)
    k = nonce
    k_inv = mod_inv(k, ORDER)
    r = mult(k, BaseU, BaseV, p)[0] % ORDER
    s = (k_inv * (z + r * private_key)) % ORDER
    return r, s 


def ECDSA_verify(message, public_key, r, s):
    z = H(message)
    w = mod_inv(s, ORDER)
    u1 = (z * w) % ORDER
    u2 = (r * w) % ORDER
    x1, y1 = mult(u1, BaseU, BaseV, p)
    x2, y2 = mult(u2, *public_key, p)
    x, y = add(x1, y1, x2, y2, p)
    return r == x % ORDER


# On teste les parametres m x et k et on regarde si on obtient les valeurs attendues

expected_r = 0x429146a1375614034c65c2b6a86b2fc4aec00147f223cb2a7a22272d4a3fdd2
expected_s = 0xf23bcdebe2e0d8571d195a9b8a05364b14944032032eeeecd22a0f6e94f8f33

m = b"A very very important message !"
x = 0xc841f4896fe86c971bedbcf114a6cfd97e4454c9be9aba876d5a195995e2ba8
k = 0x2c92639dcf417afeae31e0f8fddc8e48b3e11d840523f54aaa97174221faee6

private_key, public_key = ECDSA_generate_keys(x)
r, s = ECDSA_sign(m, x, k)

print(hex(r)[2:])
print(hex(s)[2:])
expected_r_hex = hex(expected_r)[2:].lower()  # Convertit en chaîne hexadécimale et en minuscules.
expected_s_hex = hex(expected_s)[2:].lower()  # Convertit en chaîne hexadécimale et en minuscules.
print(hex(r)[2:].lower() == expected_r_hex)
print(hex(s)[2:].lower() == expected_s_hex)
print(ECDSA_verify(m, public_key, r, s))
