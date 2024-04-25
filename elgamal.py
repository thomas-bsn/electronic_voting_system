from algebra import mod_inv, int_to_bytes
from random import randint

PARAM_P = 0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597

PARAM_Q = 0x8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3

PARAM_G = 0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659


### call bruteLog with p = PARAM_P and g = PARAM_G

def bruteLog(g, c, p):
    s = 1
    for i in range(p):
        if s == c:
            return i
        s = (s * g) % p
        if s == c:
            return i + 1
    return -1

def EG_generate_keys():
    x = randint(1, PARAM_Q - 1)
    y = pow(PARAM_G, x, PARAM_P)
    return (x, y)

## multiplicative version
def EGM_encrypt(m, y, PARAM_P, PARAM_G):
    k = randint(2, PARAM_P - 1)
    c1 = pow(PARAM_G, k, PARAM_P)
    c2 = (m * pow(y, k, PARAM_P)) % PARAM_P
    return (c1, c2)

## additive version
def EGM_encrypt2(m, y, PARAM_P, PARAM_G):
    k = randint(2, PARAM_P - 1)
    c1 = pow(PARAM_G, k, PARAM_P)
    c2 = pow(y, k, PARAM_P)*pow(PARAM_G, m, PARAM_P) % PARAM_P
    return (c1, c2)

def EG_decrypt(c1, c2, x, PARAM_P):
    s = pow(c1, x, PARAM_P)
    m = (c2 * mod_inv(s, PARAM_P)) % PARAM_P
    return m

# Homomorphic encryption : multiplicative version

# Valeurs données par l'exercice pour le test
m1 = 0x26616b7368f687c5c3142f806d500d2ce57b1182c9b25bf4efa09529424b
m2 = 0x1c1c871caabca15828cf08ee3aa3199000b94ed15e743c3

def homomorphic_multiplication(m1, m2):
    private_key, public_key = EG_generate_keys()

    r1, c1 = EGM_encrypt(m1, public_key, PARAM_P, PARAM_G)
    r2, c2 = EGM_encrypt(m2, public_key, PARAM_P, PARAM_G)

    r3 = (r1 * r2) % PARAM_P
    c3 = (c1 * c2) % PARAM_P

    m3 = EG_decrypt(r3, c3, private_key, PARAM_P)

    if m3 == (m1 * m2) % PARAM_P:
        return True
    else:
        return False

# print(homomorphic_multiplication(m1, m2))

# Homomorphic encryption : additive version 

def homomorphic_addition(L):
    private_key, public_key = EG_generate_keys()

    r, c = 1, 1
    for m in L:
        r_i, c_i = EGM_encrypt2(m, public_key, PARAM_P, PARAM_G)
        r = (r * r_i) % PARAM_P 
        c = (c * c_i) % PARAM_P 

    gm = EG_decrypt(r, c, private_key, PARAM_P)

    m_decoded = bruteLog(PARAM_G, gm, PARAM_P)

    return m_decoded == sum(L)

# print(homomorphic_addition([1, 0, 1, 1, 0]))
