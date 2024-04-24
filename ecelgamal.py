from rfc7748 import x25519, add, sub, computeVcoordinate, mult
from algebra import mod_inv, int_to_bytes
from random import randint
from elgamal import bruteLog

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
    S = add(message[0], message[1], shared_secret[0], shared_secret[1], p)
    return R, S

def ECEG_decrypt(x, y, private_key):
    shared_secret_point = mult(private_key, x[0], x[1], p)
    decrypted_message_point = sub(y[0], y[1], shared_secret_point[0], shared_secret_point[1], p)
    return decrypted_message_point


# On teste l'homomorphisme de l'addition
L= [1, 0, 1, 1, 0]

def test_homophoric_add(L):
    publickey, privatekey = ECEG_generate_keys()
    r_index = (0, 0)
    c_index = (0, 0)
    L = [EGencode(m) for m in L]

    encrypted_results = []
    for message in L:
        r, c = ECEG_encrypt(message, privatekey)
        encrypted_results.append((r, c))

    r_list = [r for r, c in encrypted_results]
    c_list = [c for r, c in encrypted_results]

    for r in r_list:
        r_index = add(r_index[0], r_index[1], r[0], r[1], p)

    for c in c_list:
        c_index = add(c_index[0], c_index[1], c[0], c[1], p)

    decrypted_message = ECEG_decrypt(r_index, c_index, publickey)
    m_result = bruteECLog(decrypted_message[0], decrypted_message[1], p)
    return m_result == 3


print(test_homophoric_add(L))
