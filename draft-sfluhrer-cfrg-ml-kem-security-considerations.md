---
title: "ML-KEM Security Considerations"
abbrev: "ML-KEM Security"
category: info

docname: draft-sfluhrer-cfrg-ml-kem-security-considerations-latest
submissiontype: IRTF
consensus: true
date:
v: 3
area: "IRTF"
workgroup: "Crypto Forum"
stand_alone: true
ipr: trust200902
keyword:
 - ML-KEM
coding: UTF-8
venue:
  group: "Crypto Forum"
  type: "Research Group"
  mail: "cfrg@irtf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/cfrg/"
  github: "sfluhrer/ml-kem-security-considerations"
  latest: "https://sfluhrer.github.io/ml-kem-security-considerations/draft-sfluhrer-cfrg-ml-kem-security-considerations.html"

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
- fullname: Kevin Milner
  organization: Quantinuum
  email: kamilner@kamilner.ca
- fullname: Daniel Shiu
  organization: Arqit Quantum Inc
  email: daniel.shiu@arqit.uk

normative:

  FIPS203:
    target: https://doi.org/10.6028/NIST.FIPS.203
    title: Module-Lattice-Based Key-Encapsulation Mechanism Standard
    seriesinfo:
      "NIST": "FIPS 203"
    date: August 2024


informative:

  RFC4253:
  RFC4086:
  RFC6278:
  RFC8446:
  RFC9180:
  RFC9528:
  I-D.ietf-core-oscore-groupcomm:
  I-D.connolly-cfrg-hpke-mlkem:
  CDM23:
    title: "Keeping Up with the KEMs: Stronger Security Notions for KEMs and automated analysis of KEM-based protocols"
    target: https://eprint.iacr.org/2023/1933.pdf
    date: 2023
    author:
      -
        ins: C. Cremers
        name: Cas Cremers
        org: CISPA Helmholtz Center for Information Security
      -
        ins: A. Dax
        name: Alexander Dax
        org: CISPA Helmholtz Center for Information Security
      -
        ins: N. Medinger
        name: Niklas Medinger
        org: CISPA Helmholtz Center for Information Security

  KEMMY24:
    title: "Unbindable Kemmy Schmidt: ML-KEM is neither MAL-BIND-K-CT nor MAL-BIND-K-PK"
    target: https://eprint.iacr.org/2024/523.pdf
    date: 2024
    author:
      -
        ins: S. Schmieg
        name: Sophie Schmieg

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

NIST standardized ML-KEM as FIPS 203 in August 2024.  This document discusses
how to use ML-KEM and how to use it within protocols - that is, what problem it solves,
and what you need to do to use it securely.

--- middle

# Introduction

A Cryptographically Relevant Quantum Computer (CRQC) is a large and reliable Quantum Computer that can break protocols which rely on the
traditional RSA, DH, or ECDH methods of securely exchanging keys.  Even
though it is not believed that, at the time of this writing, there exists a CRQC,
there still remains the possibility that an adversary may record the protocol
exchange, and then later (when they have access to a CRQC) go ahead and read
the traffic.

Because of this threat, NIST has published FIPS 203 {{FIPS203}}, which standardizes a method for allowing two systems to securely exchange keying material and which is not vulnerable to a CRQC.
This method is based on module lattices, and is called ML-KEM.

ML-KEM is a Key Encapsulation Mechanism (KEM), which can be used to generate a shared secret key between two parties.
A KEM is a public key mechanism where one side (Alice) can generate a public/private key pair, and send the public key to the other side (Bob).
Bob then can use it to generate both a ciphertext and a shared secret key.
Bob then sends the ciphertext to Alice, who uses her private key to generate the shared secret key.
The idea is that someone in the middle, listening into the exchanged public keys and ciphertexts will not be able to recover the shared secret key that Alice and Bob learns.
Hence, Alice and Bob can use their shared secret key to establish secure symmetric communication.

One common misunderstanding of the term KEM is the expectation that Bob freely chooses the
shared secret, and encrypts that when sending to Alice.
While there do exist KEMs where this is true, this is not true for ML-KEM.
In ML-KEM is that randomness from both sides are used to contribute to the
shared secret. That is, ML-KEM internally generates the shared secret in a
way that Bob cannot select the value. Now, Bob can generate a number of
ciphertext/shared secret pairs, and select the shared secret that he prefers,
but he cannot freely choose it or make the secrets across two different ML-KEM exchanges be
equal.

A KEM (such as ML-KEM) sounds like it may be a drop-in replacement for
Diffie-Hellman (and in some scenarios, it can be).
However this is not always the case. In Diffie-Hellman, the parties
exchange two public keys, whereas in a KEM, the ciphertext is necessarily a
function of Alice&apos;s public key, and thus can only be useful only with that
specific public key. Additionally, a KEM differs from Diffie-Hellman which is
asynchronous and non-interactive. In particular, for an &apos;ephemeral-ephemeral&apos;
key establishment, an encapsulator cannot pre-emptively initiate a key
establishment, but requires an encapsulation key. Nor can participants compute
parts of the key establishment in parallel as is the case with
Diffie-Hellman. As long as the application can handle larger public keys and
ciphertexts, a KEM is a drop-in replacement for &apos;ephemeral-ephemeral&apos; key
exchange in protocols like TLS {{RFC8446}}, SSH {{RFC4253}}, Wireguard {{WIRE}}, and EDHOC {{RFC9528}} as well as
&apos;static-ephemeral&apos; key exchange in protocols like ECIES/HPKE {{RFC9180}},
that is, in cases where Alice has a long term public key, and Bob can use that long term public key to establish communication.
A KEM is not a drop-in replacement in applications such as the Diffie-Hellman
ratchet in Signal {{SIGNAL}}, implicit &apos;ephemeral-static&apos; DH authentication
in Noise {{NOISE}}, WireGuard {{WIRE}}, and EDHOC {{RFC9528}}, and
&apos;static-static&apos; configurations in CMS {{RFC6278}} and Group OSCORE
{{I-D.ietf-core-oscore-groupcomm}}, where both sides have long-term public
keys.

ML-KEM can also be used to perform public key encryption, that is, where a sender encrypts a message with a public key, and only the holder of the private key can decrypt the message.
To use ML-KEM for this task, it is recommended that you use it within the Hybrid Public Key Encryption framework {{RFC9180}} to perform the operations.
You can use {{I-D.connolly-cfrg-hpke-mlkem}}, which is three ML-KEM parameter sets that has been proposed for HPKE.

# Using ML-KEM

To use ML-KEM, there are three steps involved:

## ML-KEM Key Generation

The first step for Alice is to generate a public and private keypair.

In FIPS 203, the key generation function is `ML-KEM.KeyGen()` (see section 7.1 of
{{FIPS203}}).  It internally calls the random number generator for a seed and
produces both a public key (known as an encapsulation key in FIPS 203) and a
private key (known as a decapsulation key). The seed can be securely stored,
but must be treated with the same safeguards as the private key.
The seed format allows fast
reconstruction of the expanded key pair format, and elides the need for
format checks of the expanded key formats.
Other intermediate data besides the matrix A_hat must be securely deleted.
A_hat may be saved for repeated Decapsulation operation(s) with the same decapsulation key.

The public key can be freely published (and Bob will need it for his part of
the process); this step may be performed simply by transmitting the key to
Bob.  However, the private key (in either format) must be kept secret.

It is essential that the public key is generated correctly when the initial
key generation is performed. Lattice public keys consist of a lattice and a secret
hidden by an error term; if additional error can be introduced into the
public key generation stage, then the success of decapsulation can reveal
enough of the secret that successive queries determine the private
key. Notably, this means a public key can be &apos;poisoned&apos; such that a future
adversary can recover the private key even though it will appear correct in
normal usage.

## ML-KEM Encapsulation

The second step is for Bob to generate a ciphertext and a shared secret key.

To perform this step, Bob would first run the Encapsulation Key Check on
Alice&apos;s public key as outlined at the beginning of section 7.2 of
{{FIPS203}}.  If that test passes, then Bob would perform what FIPS 203
terms as ML-KEM.Encaps() (see section 7.2 of {{FIPS203}}).  This step takes
the validated public key, internally calls the random number generator for a
seed, and produces both a ciphertext and a 32-byte shared secret
key.
Intermediate data other than the ciphertext, shared secret key and the matrix A_hat (and the "matrix data" internal to ML-KEM, which can be deduced from the public key) must be securely deleted.
The matrix A_hat may be saved and reused for later encapsulation operations with the same encapsulation key.

The ciphertext can be transmitted back to Alice; if the exchange is
successful, the 32-byte shared secret key will be the key shared with Alice.

It may be that some libraries combine the validation and the encapsulation
step; implementations should determine whether the library they are using does. For static
public keys, the Encapsulation Key Check only needs to be performed once.

## ML-KEM Decapsulation

The third and final step is for Alice to take the ciphertext and generate the
shared secret key.

To perform this step, Alice would first run the Decapsulation Key Check on
Bob&apos;s ciphertext as outlined at the beginning of section 7.3 of {{FIPS203}}.
If that test passes, then Alice would perform what FIPS 203 terms as
`ML-KEM.Decaps()` (see section 7.3 of {{FIPS203}}).  This step takes the
ciphertext from Bob and the private key that was previously generated by
Alice, and produces a 32-byte shared secret key. It also repeats some or all of the
encapsulation process to ensure that the ciphertext was created strictly
according to the specification, with invalid ciphertexts generating an unrelated 32 byte value that gives no information.
Although not necessary for the correctness of the key establishment,
this step should not be skipped as a maliciously generated ciphertext could
induce decapsulation failures that can allow an attacker to deduce the private key with a sufficient number of exchanges.
Intermediate data other than the shared secret key and the matrix A_hat must be securely deleted.
The matrix A_hat may be saved for later Decapsulation operations with the same decapsulation key.

If the exchange is successful, the 32-byte key generated on both sides will
be the same. The shared secret key is always 32 bytes for all parameter sets.

It may be that some libraries combine the validation and the encapsulation
step; implementations should determine whether the library they are using does. For static
public keys, the Decapsulation Key Check only needs to be performed once.

## ML-KEM Parameter Sets

FIPS 203 specifies three parameter sets; ML-KEM-512, ML-KEM-768 and
ML-KEM-1024.  It is assumed that Alice and Bob both know which parameter set
they use (either by negotiation or by having one selection fixed in the
protocol).

{{par-sets}} shows the sizes of the cryptographic material of ML-KEM for each parameter set, as well as their relative cryptographic strength:

|             | pk size  | sk size | ct size  | ss size  | as strong as |
| :---------- | -------: | ------: | -------: | :------: | :----------: |
| ML-KEM-512  |      800 |    1632 |      768 |       32 |      AES-128 |
| ML-KEM-768  |     1184 |    2400 |     1088 |       32 |      AES-192 |
| ML-KEM-1024 |     1568 |    3168 |     1568 |       32 |      AES-256 |
{: #par-sets title="pk = public key, sk = private key, expanded form, ct = ciphertext, ss&nbsp;=&nbsp;shared key, all lengths in bytes"}

{{par-perf}} shows an example of ML-KEM performance of each parameter set on one specific platform:

|             | key generation | encapsulation | decapsulation |
| :---------- | -------: | ------: | -------: |
| ML-KEM-512  |   244000 |  153000 |   202000 |
| ML-KEM-768  |   142000 |  103000 |   134000 |
| ML-KEM-1024 |   109000 |   77000 |    99000 |
{: #par-perf title="Single-core performance in operations per second (higher is better) on AMD Ryzen 7 7700"}
Data sourced from {{EBACS}}


As can be seen from {{par-sets}} and {{par-perf}}, ML-KEM has significantly
larger public keys and ciphertexts than ECDH but very good performance.

# KEM Security Considerations

This section pertains to KEM (Key Encapsulation Mechanisms) in general,
including ML-KEM.

A KEM requires high-quality source of entropy during both
the keypair generation and ciphertext generation steps.  If an adversary can
recover the random bits used in either of these processes, they can recover
the shared secret.  If an adversary can recover the random bits used during
key generation, they can also recover the secret key.

Standard cryptographical analysis assumes that the adversary has access only to the exchanged messages.
Depending on the deployment scenario, the adversary may have access to various side channels, such as the amount of time taken during the cryptographical computations, or possibly the power used or the electrical noise generated.
The implementor will need to assess this possibility, and possibly use an implementation that is resistant to such leakage.

Alice needs to keep her private key secret. It is recommended that they
zeroize the private key when they will have no further need of it,
that is, when they know they never need to decapsulate any further ciphertexts with it.

A KEM (including ML-KEM) provides no authentication of either communicating
party. If an adversary could replace either the public key or the ciphertext
with its own, it would generate a shared key with Alice or Bob.  Hence, it is
important that the protocol that uses a KEM lets Bob be able to verify that
the public key he obtains came from Alice and lets Alice verify that the ciphertext
came from Bob (that is, an entity that Alice is willing to
communicate with). Such verification can be performed by cryptographic
methods such as a digital signature or a MAC to verify integrity of the
protocol exchange.

# ML-KEM Security Considerations

This section pertains specifically to ML-KEM, and may not be true of KEMs in
general.

The fundamental security property of ML-KEM is that someone listening to the exchanges
(and thus obtains both the public key and the ciphertext) cannot reconstruct
the shared secret key, and this is true even if the adversary has access to a
CRQC. ML-KEM is IND-CCA2 secure; that is, it remains secure even if an
adversary is able to submit arbitrary ciphertexts used a fixed public key and observe the resulting
shared key. Submitting invalid ciphertexts to `ML-KEM.Decaps()` does not help
the attacker obtain information about the decryption key of the PKE-Decrypt
function inside the ML-KEM.Decaps(). Substituting the public key Alice sends
Bob by another public key chosen by the attacker will not help the attacker
get any information about Alice&apos;s private key, it would just make Alice and
Bob not have a same shared secret key. However, if it is possible to
substitute the copy of the public key for both Alice and Bob, an attacker can
introduce a malicious public key where the same private key can be used for
decapsulation, but the probability of decryption failure is marginally
higher. As decryption failures can leak information about the secret
decapulation key, it is important that Alice keeps a secure copy of the
public key as part of her secret key. For practical purposes, IND-CCA2 means
that ML-KEM is secure to use with static public keys.

ML-KEM requires that a source of random bits with security strength greater than or equal to the security strength of the ML-KEM parameter set be used when generating the keypair and ciphertext during ML-KEM.KeyGen() and ML-KEM.Encaps() respectively.
The cryptographic library that implements ML-KEM
may access this source of randomness internally. A fresh string of bytes must
be used for every sampling of random bytes in key generation and
encapsulation.
The random bytes should be generated securely [RFC 4086].

Alice must keep her private key secret (both private and secure from
modification).  A copy of the public key and its hash are
included in the private key and must be protected from modification.

If the ciphertext that Alice receives from Bob is tampered with (either by
small modification or by replacing it with an entirely different ciphertext),
the shared secret key that Alice derives will be uncorrelated with the shared
secret key that Bob obtains.  An attacker will not be able to determine any
information about the correct shared secret key or Alice&apos;s private key, even
if the attacker obtains Alice&apos;s modified shared secret key which is the
output of the `ML-KEM.Decaps()` function taking the modified ciphertext as input.

It is secure to reuse a public key multiple times.  That is, instead of Alice
generating a fresh public and private keypair for each exchange, Alice may
generate a public key once, and then publish that public key, and use it for
multiple incoming ciphertexts, generating multiple shared secret keys.  While
this is safe, it is recommended that if the protocol already has Alice send Bob her unauthenticated public key, they should generate a fresh keypair each time
(and zeroize the private key immediately after ML-KEM.Decaps()) to obtain Perfect Forward
Secrecy. Generally key generation of ML-KEM is very fast (see
{{par-perf}}). Hence, if Alice generates a fresh ML-KEM key each time, then even if Alice&apos;s system is subverted (either by a hacker or
a legal warrant), the previous communications remain secure (because Alice no
longer has the information needed to recover the shared secret keys).

Alice and Bob must perform the Key Check steps (the Encapsulation Key Check
on the public key for Bob, the Decapsulation Key Check on the ciphertext for
Alice).  The cryptographic libraries that Alice and Bob use may
automatically perform such checks; they should each verify that is the case.

The shared secret key for all three parameter sets, ML-KEM-512, ML-KEM-768
and ML-KEM-1024 is 32 bytes which are indistinguishable from 32-byte
pseudorandom byte-strings of 128, 192 and 256 bits of strengths
respectively. As such, the 32-byte string is suitable for both directly as a symmetric key
(for use by a symmetric cipher such as AES or a MAC), and also as input into
a Key Derivation Function.  This is in contrast to a Diffie-Hellman (or ECDH)
operation, where the output is distinguishable from random.

With ML-KEM, there is a tiny probability of decapsulation failure.
That is, even if Alice and Bob perform their roles honestly and the public key and ciphertext are transmitted correctly, there is a tiny probability that Alice and Bob will not derive the same shared key.
However, even though that is a theoretical possibility, practically speaking this will never happen.
For all three parameter sets, the probability is so low that most likely an actual decapsulation failure because of this will never be seen for any ML-KEM exchange anywhere (not only for your protocol, but over all protocols that use ML-KEM).

If the adversary has control over the ML-KEM private key, it has been shown that adversary can cause a ‘misbinding’ between the shared key and either the ciphertext or the public key.
That is, by generating an impossible private key (a key that cannot occur with the standard ML-KEM key generation process), the adversary could be able to create public keys for which different ciphertexts or public keys may result in the same shared secret (these security notions are called MAL-BIND-K-CT and MAL-BIND-K-PK in the cryptographical literature {{CDM23}} {{KEMMY24}}).
This is not a threat to normal uses of ML-KEM as a key exchange or a public key encryption method.
If ML-KEM is used as an authentication method where the shared key is used for authentication (and adversary control of the private key is possible), it may be advisable if the protocol also authenticates the public key and ciphertext as well.

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

The authors would like to thank Rebecca Guthrie and Thom Wiggers for their valuable comments and feedback.
