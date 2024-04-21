from Crypto.Random import random
from Crypto.Hash import SHA256
from algebra import mod_inv, int_to_bytes
import hashlib

from dsa import DSA_generate_keys, DSA_sign, DSA_verify, DSA_generate_nonce
from elgamal import EG_generate_keys, EGM_encrypt, EG_decrypt

PARAM_P = 0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597

PARAM_Q = 0x8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3

PARAM_G = 0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659




# Simuler un vote pour 10 électeurs et 5 candidats
def simulate_voting():
    voters = 10
    candidates = 5
    voter_keys = [DSA_generate_keys(PARAM_P, PARAM_Q, PARAM_G) for _ in range(voters)]
    elgamal_private_key, elgamal_public_key = EG_generate_keys()

    total_c1 = [1] * candidates  # Utiliser l'homomorphisme multiplicatif pour c1
    total_votes = [0] * candidates  # Initialiser pour la somme des votes

    for i in range(voters):
        chosen_candidate = random.randint(0, candidates - 1)
        vote = [1 if j == chosen_candidate else 0 for j in range(candidates)]
        encrypted_vote = [EGM_encrypt(v, elgamal_public_key, PARAM_P, PARAM_G) for v in vote]

        # Préparer une chaîne à partir des votes chiffrés pour la signature
        encrypted_vote_str = ''.join(f"{c1},{c2};" for c1, c2 in encrypted_vote)
        
        nonce = DSA_generate_nonce(PARAM_Q)
        r, s = DSA_sign(encrypted_vote_str, voter_keys[i][0], nonce, PARAM_P, PARAM_Q, PARAM_G)
        assert DSA_verify(encrypted_vote_str, r, s, voter_keys[i][1], PARAM_P, PARAM_Q, PARAM_G)

        for idx in range(candidates):
            total_c1[idx] = (total_c1[idx] * encrypted_vote[idx][0]) % PARAM_P
            total_votes[idx] = (total_votes[idx] + encrypted_vote[idx][1]) % PARAM_P

    final_tally = [EG_decrypt(total_c1[idx], total_votes[idx], elgamal_private_key, PARAM_P) for idx in range(candidates)]

    return final_tally



# Exécuter la simulation et imprimer les résultats
results = simulate_voting()
print("Résultats des votes : ", results)
