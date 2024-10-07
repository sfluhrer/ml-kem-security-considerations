---
title: ML-KEM Security Considerations
abbrev: "ML-KEM Security"
category: info

docname: draft-sfluhrer-cfrg-ml-kem-security-considerations-00
submissiontype: IRTF
number:
date: October 7, 2024
consensus: true
v: 0
area: "IRTF"
workgroup: "Crypto Forum"

author:
- fullname: Scott Fluhrer
  organization: Cisco Systems
  email: sfluhrer@cisco.com
- fullname: Quynh Dang
  organization: National Institute of Standards and Technology
  abbrev: NIST
  email: Quynh.Dang@nist.gov
- initials: J.
  surname: Preuß Mattsson
  name: John Preuß Mattsson
  org: Ericsson
  email: john.mattsson@ericsson.com

normative: 

  FIPS203:
    target: https://doi.org/10.6028/NIST.FIPS.203
    title: Module-Lattice-Based Key-Encapsulation Mechanism Standard
    seriesinfo:
      "NIST": "FIPS 203"
    date: August 2024


informative:

  RFC4253:
  RFC5990:
  RFC6278:
  RFC8446:
  RFC9180:
  RFC9528:
  I-D.ietf-core-oscore-groupcomm:

  SIGNAL:
    target: https://signal.org/docs/specifications/doubleratchet/
    title: The Double Ratchet Algorithm
    date: November 2011

  WIRE:
    target: https://www.wireguard.com/
    title: WireGuard

  NOISE:
    target: http://www.noiseprotocol.org/
    title: Noise Protocol Framework

  EBACS:
    target: https://bench.cr.yp.to/results-kem/amd64-hertz.html
    title: "eBACS: ECRYPT Benchmarking of Cryptographic Systems"

--- abstract

NIST standardized ML-KEM as FIPS 203 in August 2024.  This document discusses how to use ML-KEM - that is, what problem it solves, and how to use it securely.

--- middle

# Introduction

A large reliable quantum computer (often termed a Cryptographically Relevant Quantum Computer or CRQC) would be able to break protocols which rely on the traditional RSA, DH, or ECDH methods of securely exchanging keys.  Even though we do not believe, at the time of this writing, there exists a CRQC, there still remains the possibility that an adversary may record the protocol exchange, and then later (when they have access to a CRQC) go ahead and read the traffic.

Because of this potential threat, NIST has standardized ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism), which is standardized in FIPS 203 {{FIPS203}}.  ML-KEM is used to generate a shared secret key between two parties. One party (Alice) generates a public/private keypair, and sends the public key to the other party (Bob).  Bob uses the public key and some randomness to generate both the shared secret key and a ciphertext. Bob then sends the ciphertext to Alice, who uses her private key to generate the same shared secret key. NIST plans to standardize one or more code-based KEMs in the future.

The fundamental security property is that someone listening to the exchanges (and thus obtains both the public key and the ciphertext) cannot reconstruct the shared secret key and this is true even if the adversary has access to a CRQC. ML-KEM is IND-CCA2 secure, that is, it remains secure even if an adversary is able to submit arbitrary ciphertexts and observe the resulting shared key. Submitting invalid ciphertexts to a ML-KEM.Decaps does not help the attacker obtain information about the decryption key of the PKE-Decrypt function inside the ML-KEM.Decaps. Substituting the public key Alice sends Bob by another public key chosen by the attacker will not help the attacker get any information about Alice's private key, it would just make Alice and Bob not have a same shared secret key. For practical purposes, IND-CCA2 means that ML-KEM is secure to use with static public keys.

ML-KEM is what is termed a Key Encapsulation Mechanism. One common misunderstanding of that term is the expectation that Bob freely chooses the shared secret, and encrypts that when sending to Alice. What happens in ML-KEM is that randomness from both sides are used to contribute to the shared secret. That is, ML-KEM internally generates the shared secret in a way that Bob cannot select the value. Now, Bob can generate a number of ciphertext/shared secret pairs, and select the shared secret that he prefers, but he cannot freely choose it or make secrets shared with two parties be equal. This is different from RSA-KEM {{RFC5990}}, where Bob cannot select the value, but can encapsulate the same shared secret to many recipients.

A KEM (such as ML-KEM) sounds like it may be a drop-in replacement for Diffie-Hellman, however this is not the case. In Diffie-Hellman, the parties exchange two public keys, whereas in a KEM, the ciphertext is necessarily a function of Alice's public key, and thus can only be useful only with that specific public key. As long a the application can handle larger public keys and ciphertexts, a KEM is a drop-in replacement for 'ephemeral-ephemeral' key exchange in protocols like TLS {{RFC8446}} and SSH {{RFC4253}} as well as 'static-ephemeral' key exchange in protocols like ECIES/HPKE {{RFC9180}}. A KEM is not a drop-in replacement in applications such as the Diffie-Hellman ratchet in Signal {{SIGNAL}}, implicit 'ephemeral-static' DH authentication in Noise {{NOISE}}, Wireguard {{WIRE}}, and EDHOC {{RFC9528}}, and 'static-static' configurations in CMS {{RFC6278}} and Group OSCORE {{I-D.ietf-core-oscore-groupcomm}}, where both sides have long-term public keys. Furthermore ML-KEM is not a drop-in replacement for RSA-KEM as RSA-KEM can encapsulate the same shared secret to many recipients whereas ML-KEM cannot.

# Using ML-KEM

To use ML-KEM, there are three steps involved

## ML-KEM Key Generation

The first step for Alice is to generate a public and private keypair.

In FIPS 203, this function is termed ML-KEM.KeyGen() (see section 7.1 of {{FIPS203}}).  It internally calls the random number generator for a seed and produces both a public key (termed an encapsulation key in FIPS 203) and a private key (termed a decapsulation key).

The public key can be freely published (and Bob will need it for his part of the process); this step may be performed simply by transmitting the key to Bob.  However, the private key must be kept secret.

## ML-KEM Encapsulation

The second step is for Bob to generate a ciphertext and a shared secret key.

To perform this step, Bob would first run the Encapsulation Key Check on Alice's public key as outlined at the beginning of section 7.2 of {{FIPS203}}.
If that test passes, then Bob would perform the what FIPS 203 terms as ML-KEM.Encaps() (see section 7.2 of {{FIPS203}}).  This step takes the validated public key, internally calls the random number generator for a seed, and produces both a ciphertext and a 32-byte shared secret key.

The ciphertext can be transmitted back to Alice; if the exchange is successful, the 32-byte shared secret key will be the key shared with Alice.

It may be that some libraries combine the validation and the encapsulation step; you should check whether the library you are using does. For static public keys, the Encapsulation Key Check only needs to be performed once.

## ML-KEM Decapsulation

The third and final step is for Alice to take the ciphertext and generate the shared secret key.

To perform this step, Alice would first run the Decapsulation Key Check on Bob's ciphertext as outlined at the beginning of section 7.3 of {{FIPS203}}.
If that test passes, then Bob would perform the what FIPS 203 terms as ML-KEM.Decaps() (see section 7.3 of {{FIPS203}}).  This step takes the ciphertext from Bob and the private key that was previously generated by Alice, and produces a 32-byte shared secret key.

If the exchange is successful, the 32-byte key generated on both sides will be the same.

It may be that some libraries combine the validation and the decapsulation step; you should check whether the library you are using does.

## ML-KEM Parameter Sets

ML-KEM comes with three parameter sets; ML-KEM-512, ML-KEM-768 and ML-KEM-1024.  It is assumed that Alice and Bob both know which parameter sets they use (either by negotiation or by having one selection fixed in the protocol).

{{par-sets}} shows a summary of how those parameter sets differ:

|             | pk size  | sk size | ct size  | ss size  | as strong as |
| :---------- | -------: | ------: | -------: | :------: | :----------: |
| ML-KEM-512  |      800 |    1632 |      768 |       32 |      AES-128 |
| ML-KEM-768  |     1184 |    2400 |     1088 |       32 |      AES-192 |
| ML-KEM-1024 |     1568 |    3168 |     1568 |       32 |      AES-256 |
{: #par-sets title="pk = public key, sk = private key, ct = ciphertext, ss&nbsp;=&nbsp;shared key, all lengths in bytes"}

{{par-perf}} shows an example of ML-KEM performance {{EBACS}}:

|             | key generation | encapsulation | decapsulation |
| :---------- | -------: | ------: | -------: |
| ML-KEM-512  |   244000 |  153000 |   202000 |
| ML-KEM-768  |   142000 |  103000 |   134000 |
| ML-KEM-1024 |   109000 |   77000 |    99000 |
{: #par-perf title="Single-core performance in operation per second on AMD Ryzen 7 7700"}

As can be seen from {{par-sets}} and {{par-sets}}, ML-KEM has significantly larger public keys and ciphertexts than ECDH but very good performance.

# KEM Security Considerations

This section pertains to KEM (Key Encapsulation Mechanisms) in general, including ML-KEM

To use a KEM, you need to use a high-quality source of entropy during both the key-pair generation and ciphertext generation steps.  If an adversary can recover the random bits used in either of these processes, they can recover the shared secret.  If an adversary can recover the random bits used during key generation, they can recover the secret key.

Alice needs to keep her private key secret. It is recommended that she zeroize her private key when she will have no further need of it.

A KEM (including ML-KEM) provides no authentication of either communicating party. If an adversary could replace either the public key or the ciphertext with its own, it would generate a shared key with Alice or Bob.  Hence, it is important that the protocol that uses a KEM lets Bob be able to verify that the public key he obtains came from Alice and that the ciphertext that Alice receives came from Bob (that is, an entity that Alice is willing to communicate with).  Such verification can be performed by cryptographic methods such as digital signatures or a MAC to verify integrity of the protocol exchange transcript.

# ML-KEM Security Considerations

This section pertains specifically to ML-KEM, and may not be true of KEMs in general.

To use ML-KEM, you need a source of random bits with security strength equal to greater than the security strength of the KEM during both key generation and encapsulation steps.  The cryptographic library that implements ML-KEM may access this source of randomness internally.

Alice must keep her private key secret (both private and secure from modification).  It is recommended that she zeroizes her private key when she will have no further need of it.

If the ciphertext that Alice receives from Bob is tampered with (either by small modification or by replacing it with an entirely different ciphertext), the shared secret key that Alice derives will be uncorrelated with the shared secret key that Bob obtains.  An attacker will not be able to determine any information about the correct shared secret key or Alice's private key, even if the attacker obtains Alice's modified shared secret key which is the output of the ML-KEM.Decaps function taking the modified ciphertext as input.

It is secure to reuse a public key multiple times.  That is, instead of Alice generating a fresh public and private keypair for each exchange, Alice may generate a public key once, and then publish that public key, and use it for multiple incoming ciphertexts, generating multiple shared secret keys.  While this is safe, it is recommended that if the protocol allows it (if Alice and Bob exchange messages anyways) that Alice generates a fresh keypair each time (and zeroize the private key immediately after) to obtain Perfect Forward Secrecy. Be noted that generally key generation of ML-KEM is very fast, see {{par-perf}}. That is, if Alice's system is subverted (either by a hacker or a legal warrant), the previous communications remain secure (because Alice no longer has the information needed to recover the shared secret keys).

Alice and Bob must perform the Key Check steps (the Encapsulation Key Check on the public key for Bob, the Decapsulation Key Check on the ciphertext for Alice).  The cryptographical libraries that Alice and Bob use may automatically perform such checks; if so, that should be verified.

The shared secret key for all three parameter sets, ML-KEM-512, ML-KEM-768 and ML-KEM-1024 are 32 bytes which are indistinguishable from 32-byte pseudorandom byte-strings of 128, 192 and 256 bits of strengths respectively. As such, it is suitable both to use directly as a symmetric key (for use by a symmetric cipher such as AES or a MAC), and for inserting into a Key Derivation Function.  This is in contrast to a Diffie-Hellman (or ECDH) operation, where the output is distinguishable from random.

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}
