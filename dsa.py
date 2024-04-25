from Crypto.Random import random
from Crypto.Hash import SHA256
from algebra import mod_inv
from Crypto.PublicKey import DSA

## parameters from MODP Group 24 -- Extracted from RFC 5114

PARAM_P = 0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597

PARAM_Q = 0x8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3

PARAM_G = 0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659

def H(message):
    h = SHA256.new(message)
    return (int(h.hexdigest(), 16))

def DSA_generate_nonce(q):
    return random.randint(1, q-1)


def DSA_generate_keys(PARAM_P, PARAM_Q, PARAM_G):
    key = DSA.generate(2048, randfunc=None)
    key.p = PARAM_P
    key.q = PARAM_Q
    key.g = PARAM_G
    private_key = random.StrongRandom().randint(1, key.q - 1)
    public_key = pow(key.g, private_key, key.p)
    return private_key, public_key


def DSA_sign(message, private_key, k, PARAM_P, PARAM_Q, PARAM_G):
    r = pow(PARAM_G, k, PARAM_P) % PARAM_Q
    hash_value = int.from_bytes(SHA256.new(message.encode()).digest(), byteorder='big')
    s = (mod_inv(k, PARAM_Q) * (hash_value + private_key * r)) % PARAM_Q
    return r, s


def DSA_verify(message, r, s, public_key, PARAM_P, PARAM_Q, PARAM_G):
    w = mod_inv(s, PARAM_Q)
    hash_value = int.from_bytes(SHA256.new(message.encode()).digest(), byteorder='big')
    u1 = (hash_value * w) % PARAM_Q
    u2 = (r * w) % PARAM_Q
    v = ((pow(PARAM_G, u1, PARAM_P) * pow(public_key, u2, PARAM_P)) % PARAM_P) % PARAM_Q
    return v == r


# On teste les parametres m x et k et on regarde si on obtient les valeurs attendues

"""
expected_r = 0x5ddf26ae653f5583e44259985262c84b483b74be46dec74b07906c5896e26e5a
expected_s = 0x194101d2c55ac599e4a61603bc6667dcc23bd2e9bdbef353ec3cb839dcce6ec1

m = "An important message !"
k = 0x7e7f77278fe5232f30056200582ab6e7cae23992bca75929573b779c62ef4759
x = 0x49582493d17932dabd014bb712fc55af453ebfb2767537007b0ccff6e857e6a3

r, s = DSA_sign(m, x, k, PARAM_P, PARAM_Q, PARAM_G)

print(hex(r)[2:])
print(hex(s)[2:])
expected_r_hex = hex(expected_r)[2:].lower()  # Convertit en chaîne hexadécimale et en minuscules.
expected_s_hex = hex(expected_s)[2:].lower()  # Convertit en chaîne hexadécimale et en minuscules.
print(hex(r)[2:].lower() == expected_r_hex)
print(hex(s)[2:].lower() == expected_s_hex)
"""



