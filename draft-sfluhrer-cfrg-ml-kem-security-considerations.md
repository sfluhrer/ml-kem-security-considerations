---
title: ml-kem-security-considerations
abbrev: "ml-kem security"
category: info

docname: draft-sfluhrer-cfrg-ml-kem-security-considerations-latest
submissiontype: IRTF
number:
date:
consensus: true
v: 3
area: "IRTF"
workgroup: "Crypto Forum"

author:
    fullname: Scott Fluhrer
    organization: Cisco Systems
    email: sfluhrer@cisco.com

% If you contribute to this document, feel free to add yourself to the author list.

informative:


--- abstract

NIST standardized ML-KEM as FIPS 203 in August 2024.  This document discusses how to use ML-KEM - that is, what problem it solves, and how to use it securely.

--- middle

# Introduction

A large reliable Quantum Computer (often termed a Cryptographically Relevant Quantum Computer or CRQC) would be able to break protocols which rely on the tradtional RSA, DH or ECDH methods of securely exchanging keys.  Even though we do not believe, at the time of this writing, there exists a CRQC, there still remains the possibility that a adversary may record the protocol exchange, and then later (when they have access to a CRQC) go ahead and read the traffic.

Because of this potential threat, NIST has standardized ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism), which is standardized in FIPS 203.  ML-KEM is used to generate a shared secret between two parties. One party (Alice) generates a public/private keypair, and sends the public key to the other side (Bob).  Bob uses the public key and some randomness to generate both the shared secret and a ciphertext.  Bob then sends the ciphertext to Alice, who uses her private key to generate the same shared secret.

The fundamental security propery is that someone listening to the exchanges (and thus obtains both the public key and the ciphertext) cannot reconstruct the shared secret; and this is true even if the adversary has access to a CRQC.

ML-KEM is what is termed a Key Encapsulation Mechanism.  One common misunderstanding of that term is the expectation that Bob freely chooses the shared secret, and encrypts that when sending to Alice.  Instead, randomness from both sides are used to contribute to the shared secret.  What actually happens is that ML-KEM internally generates the shared secret in a way that Bob cannot select the value.  Now, Bob can generate a number of ciphertext/shared secret pairs, and select the shared secret that he prefers, but he cannot freely choose it.  

A KEM (such as ML-KEM) sounds like it may be a drop-in replacement for Diffie-Hellman, however there is one scenario where this doesn't work.  If the protocol uses DH in a 'static-static' configuration, that is, if both sides have long-term public keys, then ML-KEM is not suitable.  That is because the ciphertext is necessarily a function of Alice's public key, and thus can only be useful only with that specific public key.

# Using ML-KEM

To use ML-KEM, there are three steps involved

## ML-KEM Key Generation

The first step for Alice is to generate a public and private keypair.

[MORE HERE]

## ML-KEM Encapsulation

The second step is for Bob to generate a ciphertext and shared secret.

## ML-KEM Decapsulation

The third and final step is for Alice to take the ciphertext and generate the shared secret.

## ML-KEM Parameter sets

ML-KEM comes with three parameter sets; ML-KEM-512, ML-KEM-768 and ML-KEM-1024.  It is assumed that ALice and Bob both know which parameter sets they use (either by negotiation or by having one choice fixed in the protocol).

Here is a summary of how those parameter sets differ:

|             | pk size  | sk size | ct size  | ss size  | as strong as |
| :---------- | -------: | ------: | -------: | :------: | :----------: |
| ML-KEM-512  |      800 |    1632 |      768 |       32 |      AES-128 |  
| ML-KEM-768  |     1184 |    2400 |     1088 |       32 |      AES-192 |
| ML-KEM-1024 |     1568 |    3168 |     1568 |       32 |      AES-256 |

(pk = public key, sk = private key, ct = ciphertext, ss = shared secret, all lengths in bytes)

# Conventions and Definitions

{::boilerplate bcp14-tagged}

I don't know if we need anything in this section.

# KEM Security Considerations

This section pertains to KEM (Key Encapsulation Mechanisms) in general, including ML-KEM

To use a KEM, you need to use good random bits [better terminology here please] during both the public key generation and ciphertext generation steps.  If an adversary can recover the random bits used in either of these processes, he can recover the shared secret.

Alice needs to keep her private key secret.  It is recommended that she zeroize her private key when she will have no further need of it.

A KEM provides no authentication; it is important that the protocol that uses a KEM lets Bob be able to verify that the public key he obtains comes from Alice and that the ciphertext that Alice receives came from Bob (that is, an entity that Alice is willing to communicate with).

# ML-KEM Security Considerations

This section pertains specifically to ML-KEM; this is in addition to the security considerations that apply to all KEMs

If the ciphertext that Alice receives from Bob is tampered with (either by small modification or by replacing it with an entirely different ciphertext), the shared secret that Alice derives will be uncorrelated with the shared secret that Bob obtains.  An attacker will not be able to determine any information about the correct shared secret or Alice's private key, even if he obtains Alice's modified shared secret.

It is secure to reuse a public key multiple times.  That is, instead of Alice generating a fresh public and private keypair for each exchange, Alice may generate a public key once, and then publish that public key, and use it for multiple incoming ciphertexts, generating multiple shared secrets.  While this is safe, it is recommended that if the protocol allows it (if Alice and Bob exchange messages anyways) that Alice generates a fresh keypair each time (and zeroize the private key immediately after) to obtain Perfect Forward Secrecy.  That is, if Alice's system is subverted (either by a hacker or a legal warrent), the previous communications remain secure (because Alice no longer has the information needed to recover the shared secret).

The shared secret for all three parameter sets are 32 bytes which are indistinguishable from random (by someone observing only the public key and the ciphertext).  As such, it is suitable both to use directly as symmetric keying material, and for inserting into a Key Derivation Function.  This is in contrast to a Diffie-Hellman (or ECDH) operation, where the output is distinguishable from random.

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

If you lightly edit this text or just review it, please feel free to add yourself to the acknowledgements.
