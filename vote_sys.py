from Crypto.Random import random
from Crypto.Hash import SHA256
from algebra import mod_inv, int_to_bytes
import hashlib

from dsa import DSA_generate_keys, DSA_sign, DSA_verify, DSA_generate_nonce, PARAM_P, PARAM_Q, PARAM_G
from elgamal import EG_generate_keys, EGM_encrypt, EG_decrypt, bruteLog, PARAM_P as EG_PARAM_P


def simulate_voting_system(num_voters=10, num_candidates=5):

    voters_keys = [DSA_generate_keys(PARAM_P, PARAM_Q, PARAM_G) for _ in range(num_voters)]
    
    votes = []  
    public_keys = [public_key for _, public_key in voters_keys]


    for private_key, _ in voters_keys:
        chosen_candidate = random.randint(0, num_candidates-1)
        vote = [0] * num_candidates
        vote[chosen_candidate] = 1
        

        encrypted_vote = [EGM_encrypt(v, public_keys[random.randint(0, num_voters-1)], PARAM_P, PARAM_G) for v in vote]
        
        vote_str = ''.join(str(v[1]) for v in encrypted_vote) 

        k = DSA_generate_nonce(PARAM_Q)
        r, s = DSA_sign(vote_str, private_key, k, PARAM_P, PARAM_Q, PARAM_G)  
        
        votes.append((encrypted_vote, (r, s)))
    
    aggregated_votes = [1] * num_candidates 
    for vote, _ in votes:
        for i in range(num_candidates):
            aggregated_votes[i] = (aggregated_votes[i] * vote[i][1]) % PARAM_P
    
    decrypted_aggregates = [EG_decrypt(r, aggregated_votes[i], private_key, PARAM_P) for i in range(num_candidates)]

    results = []
    for i in range(num_candidates):
        results.append(bruteLog(PARAM_G, decrypted_aggregates[i], PARAM_P))
    
    return results

"""
# Call the simulation function
election_results = simulate_voting_system()
print("Election Results:", election_results)
"""