from Crypto.Random import random
from Crypto.Hash import SHA256
from algebra import mod_inv, int_to_bytes
import hashlib

from dsa import DSA_generate_keys, DSA_sign, DSA_verify, DSA_generate_nonce, PARAM_P, PARAM_Q, PARAM_G
from elgamal import EG_generate_keys, EGM_encrypt, EG_decrypt, bruteLog, PARAM_P as EG_PARAM_P


def simulate_voting_system(num_voters=10, num_candidates=5):
    # Génération des clés pour chaque électeur
    print("Etape 1 : Génération des clés pour chaque électeur")
    voters_keys = [DSA_generate_keys(PARAM_P, PARAM_Q, PARAM_G) for _ in range(num_voters)]
    
    votes = []  # Stocke les tuples de (list of encrypted messages, signature)
    public_keys = [public_key for _, public_key in voters_keys]

    print("Etape 2 : Chiffrement des votes et signature")
    for private_key, _ in voters_keys:
        chosen_candidate = random.randint(0, num_candidates-1)
        vote = [0] * num_candidates
        vote[chosen_candidate] = 1
        
        # Encrypt each part of the vote
        encrypted_vote = [EGM_encrypt(v, public_keys[random.randint(0, num_voters-1)], PARAM_P, PARAM_G) for v in vote]
        
        # Serialization of the vote for signing
        vote_str = ''.join(str(v[1]) for v in encrypted_vote)  # Create a string representation of the encrypted vote values

        # Signature
        k = DSA_generate_nonce(PARAM_Q)
        r, s = DSA_sign(vote_str, private_key, k, PARAM_P, PARAM_Q, PARAM_G)  # Sign the hash directly
        
        votes.append((encrypted_vote, (r, s)))
    
    print("Etape 3 : Agrégation des votes")
    # Aggregate the votes using homomorphic property
    aggregated_votes = [1] * num_candidates  # start with neutral element for multiplication
    for vote, _ in votes:
        for i in range(num_candidates):
            aggregated_votes[i] = (aggregated_votes[i] * vote[i][1]) % PARAM_P
    
    print("Etape 4 : Décryptage et comptage des votes")
    # Decrypt and count votes for each candidate
    decrypted_aggregates = [EG_decrypt(r, aggregated_votes[i], private_key, PARAM_P) for i in range(num_candidates)]

    results = []
    for i in range(num_candidates):
        results.append(bruteLog(PARAM_G, decrypted_aggregates[i], PARAM_P))
        print("Candidat", i+1, ":", results[i])

    
    return results


# Call the simulation function
election_results = simulate_voting_system(1,1)
print("Election Results:", election_results)
