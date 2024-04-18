from rfc7448 import x25519, add, computeVcoordinate, mult
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


def ECDSA_generate_keys():
    private_key = randint(1, ORDER-1)
    public_key = mult(private_key, BaseU, BaseV, p)
    return private_key, public_key


def ECDSA_sign("""TBC"""):
    return ("""TBC""")    


def ECDSA_verify("""TBC"""):
    return """TBC"""