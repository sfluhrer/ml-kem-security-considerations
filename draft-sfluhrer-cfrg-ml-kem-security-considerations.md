---
title: ML-KEM Security Considerations
abbrev: "ML-KEM Security"
category: info

docname: draft-sfluhrer-cfrg-ml-kem-security-considerations-1
submissiontype: IRTF
consensus: true
date: October 11, 2024
v: 1
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
  RFC5990:
  RFC6278:
  RFC8446:
  RFC9180:
  RFC9528:
  I-D.ietf-core-oscore-groupcomm:

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
how to use ML-KEM - that is, what problem it solves, and how to use it
securely.

--- middle

# Introduction

A large reliable quantum computer (often termed a Cryptographically Relevant
Quantum Computer or CRQC) would be able to break protocols which rely on the
traditional RSA, DH, or ECDH methods of securely exchanging keys.  Even
though we do not believe, at the time of this writing, there exists a CRQC,
there still remains the possibility that an adversary may record the protocol
exchange, and then later (when they have access to a CRQC) go ahead and read
the traffic.

Because of this potential threat, NIST has standardized ML-KEM
(Module-Lattice-Based Key-Encapsulation Mechanism), which is standardized in
FIPS 203 {{FIPS203}}.  ML-KEM is used to generate a shared secret key between
two parties. One party (Alice) generates a public/private keypair, and sends
the public key to the other party (Bob).  Bob uses the public key and some
randomness to generate both the shared secret key and a ciphertext. Bob then
sends the ciphertext to Alice, who uses her private key to generate the same
shared secret key. NIST plans to standardize one or more code-based KEMs in
the future.

ML-KEM is a Key Encapsulation Mechanism (KEM). One common misunderstanding of
that term is the expectation that Bob freely chooses the shared secret, and
encrypts that when sending to Alice. What happens in ML-KEM is that
randomness from both sides are used to contribute to the shared secret. That
is, ML-KEM internally generates the shared secret in a way that Bob cannot
select the value. Now, Bob can generate a number of ciphertext/shared secret
pairs, and select the shared secret that he prefers, but he cannot freely
choose it or make secrets shared with two parties be equal. This is different
from RSA-KEM {{RFC5990}}, where Bob cannot select the value, but can
encapsulate the same shared secret to many recipients.

A KEM (such as ML-KEM) sounds like it may be a drop-in replacement for
Diffie-Hellman, however this is not the case. In Diffie-Hellman, the parties
exchange two public keys, whereas in a KEM, the ciphertext is necessarily a
function of Alice's public key, and thus can only be useful only with that
specific public key. Additionally, a KEM differs from Diffie-Hellman which is
asynchronous and non-interactive. In particular, for an 'ephemeral-ephemeral'
key establishment, an encapsulator cannot pre-emptively initiate a key
establishment, but requires an encapulation key. Nor can participants compute
parts of the key establishment in parallel as is the case with
Diffie-Hellman. As long a the application can handle larger public keys and
ciphertexts, a KEM is a drop-in replacement for 'ephemeral-ephemeral' key
exchange in protocols like TLS {{RFC8446}} and SSH {{RFC4253}} as well as
'static-ephemeral' key exchange in protocols like ECIES/HPKE {{RFC9180}}. A
KEM is not a drop-in replacement in applications such as the Diffie-Hellman
ratchet in Signal {{SIGNAL}}, implicit 'ephemeral-static' DH authentication
in Noise {{NOISE}}, Wireguard {{WIRE}}, and EDHOC {{RFC9528}}, and
'static-static' configurations in CMS {{RFC6278}} and Group OSCORE
{{I-D.ietf-core-oscore-groupcomm}}, where both sides have long-term public
keys. Furthermore ML-KEM is not a drop-in replacement for RSA-KEM as RSA-KEM
can encapsulate the same shared secret to many recipients whereas ML-KEM
cannot.

# IND-CCA

The fundamental security property is that someone listening to the exchanges
(and thus obtains both the public key and the ciphertext) cannot reconstruct
the shared secret key and this is true even if the adversary has access to a
CRQC. ML-KEM is IND-CCA2 secure, that is, it remains secure even if an
adversary is able to submit arbitrary ciphertexts and observe the resulting
shared key. Submitting invalid ciphertexts to `ML-KEM.Decaps()` does not help
the attacker obtain information about the decryption key of
`K-PKE.Decrypt()`, inside `ML-KEM.Decaps()`. Substituting the public key
Alice sends Bob by another public key chosen by the attacker will not help
the attacker get any information about Alice's private key, it would just
make Alice and Bob not have a same shared secret key. However, if it is
possible to substitute the copy of the public key for both Alice and Bob, an
attacker can introduce a malicious public key where the same private key can
be used for decapsulation, but the probability of decryption failure is
marginally higher. As decryption failures can leak information about the
secret decapulation key, it is important that Alice keeps a secure copy of
the public key as part of her secret key. For practical purposes, IND-CCA2
means that ML-KEM is secure to use with static public keys.

# Properties beyond IND-CCA

There are security properties beyond IND-CCA such as those studied in [CAS].
There are many variants. MAL-X is hardest to achieve, but failure to achieve
it hasn't lead to practical attacks at present. LEAK-X is in the middle, and
failure to be LEAK-X has lead to reencapsulation attacks [PQXDH]. ML-KEM achieves
LEAK-X, but not all MAL-X. The latter is discussed in the 'Security Properties' 
section below.

# Using ML-KEM

To use ML-KEM, there are three steps involved:

## ML-KEM Key Generation

The first step for Alice is to generate a public and private keypair.

In FIPS 203, this function is `ML-KEM.KeyGen()` (see section 7.1 of
{{FIPS203}}).  It internally calls the random number generator for a seed and
produces both a public key (termed an encapsulation key for KEMs) and a
private key (termed a decapsulation key). The seed can be securely retained
as the 64-byte seed format of the decapsulation key, but must be treated with
the same safeguards as the private key. The seed format allows fast
reconstruction of the expanded key pair format, and elides the need for
format checks of the expanded key formats. Other intermediate data must be
securely deleted.

The public key can be freely published (and Bob will need it for his part of
the process); this step may be performed simply by transmitting the key to
Bob.  However, the private key in either format must be kept secret.

## ML-KEM Encapsulation

The second step is for Bob to generate a ciphertext and a shared secret key.

To perform this step, Bob would first run the Encapsulation Key Check on
Alice's public key as outlined at the beginning of section 7.2 of
{{FIPS203}}.  If that test passes, then Bob would perform the what FIPS 203
terms as ML-KEM.Encaps() (see section 7.2 of {{FIPS203}}).  This step takes
the validated public key, internally calls the random number generator for a
seed, and produces both a ciphertext and a 32-byte shared secret
key. Intermediate data other than the ciphertext and shared secret key must
be securely deleted (with the possible exception of "matrix data" which does
not depend on Bob's seed and can be reused over multiple encapsulations with
the same public key).

The ciphertext can be transmitted back to Alice; if the exchange is
successful, the 32-byte shared secret key will be the key shared with Alice.

It may be that some libraries combine the validation and the encapsulation
step; you should check whether the library you are using does. For static
public keys, the Encapsulation Key Check only needs to be performed once.

## ML-KEM Decapsulation

The third and final step is for Alice to take the ciphertext and generate the
shared secret key.

To perform this step, Alice would first run the Decapsulation Key Check on
Bob's ciphertext as outlined at the beginning of section 7.3 of {{FIPS203}}.
If that test passes, then Bob would perform the what FIPS 203 terms as
`ML-KEM.Decaps()` (see section 7.3 of {{FIPS203}}).  This step takes the
ciphertext from Bob and the private key that was previously generated by
Alice, and produces a 32-byte shared secret key. It also repeats the
encapsulation process to ensure that the ciphertext was created strictly
according to the specification, implicitly rejecting ciphertexts that were
not. Although not necessary for the correctness of the key establishment,
this step should not be skipped as maliciously generated ciphertexts could
induce decapsulation failures with insecure probability.  Intermediate data
other than the shared secret key must be securely deleted (with the possible
exception of "matrix data" which can be reused over multiple decapsulations
with the same public key.)

If the exchange is successful, the 32-byte key generated on both sides will
be the same. The shared secret key is always 32 bytes, no matter the
parameter set.

It may be that some libraries combine the validation and the decapsulation
step; you should check whether the library you are using does this.

## ML-KEM Parameter Sets

ML-KEM comes with three parameter sets; ML-KEM-512, ML-KEM-768 and
ML-KEM-1024.  It is assumed that Alice and Bob both know which parameter sets
they use (either by negotiation or by having one selection fixed in the
protocol).

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

As can be seen from {{par-sets}} and {{par-sets}}, ML-KEM has significantly
larger public keys and ciphertexts than ECDH but very good performance.

# KEM Security Considerations

This section pertains to KEM (Key Encapsulation Mechanisms) in general,
including ML-KEM.

To use a KEM, you need to use a high-quality source of entropy during both
the key-pair generation and ciphertext generation steps.  If an adversary can
recover the random bits used in either of these processes, they can recover
the shared secret.  If an adversary can recover the random bits used during
key generation, they can recover the secret key.

Alice needs to keep her private key secret. It is recommended that she
zeroize her private key when she will have no further need of it.

A KEM (including ML-KEM) provides no authentication of either communicating
party. If an adversary could replace either the public key or the ciphertext
with its own, it would generate a shared key with Alice or Bob.  Hence, it is
important that the protocol that uses a KEM lets Bob be able to verify that
the public key he obtains came from Alice and that the ciphertext that Alice
receives came from Bob (that is, an entity that Alice is willing to
communicate with). Such verification can be performed by cryptographic
methods such as digital signatures or a MAC to verify integrity of the
protocol exchange transcript.

The computational binding properties for KEMs were formalized in
{{CDM23}}. The binding properties of KEMs have implications for their use in
protocols and whether those protocols are resilient against re-encapsulation
attacks or how KEMs should be integrated into protocols to achieve strong
session independence properties, say. The details of ML-KEM's binding properties
are discussed below.

# ML-KEM Security Considerations

This section pertains specifically to ML-KEM, and may not be true of KEMs in
general.

To use ML-KEM, you need a source of random bits with security strength equal
to greater than the security strength of the KEM during both key generation
and encapsulation steps.  The cryptographic library that implements ML-KEM
may access this source of randomness internally. A fresh string of bytes must
be used for every sampling of random bytes in key generation and
encapsulation. The random bytes should come from an approved RBG.

Alice must keep her private key secret (both private and secure from
modification).  It is recommended that she zeroizes her private key when she
will have no further need of it. A copy of the public key and its hash are
included in the private key and must be protected from modification. Using
the 64-byte seed format of the private key is supported, efficient, requires
less key pair checking, and provides the maximum binding property security
for {{FIPS203}}.

If the ciphertext that Alice receives from Bob is tampered with (either by
small modification or by replacing it with an entirely different ciphertext),
the shared secret key that Alice derives will be uncorrelated with the shared
secret key that Bob obtains.  An attacker will not be able to determine any
information about the correct shared secret key or Alice's private key, even
if the attacker obtains Alice's modified shared secret key which is the
output of the `ML-KEM.Decaps()` function taking the modified ciphertext as
input.

It is secure to reuse a public key multiple times.  That is, instead of Alice
generating a fresh public and private keypair for each exchange, Alice may
generate a public key once, and then publish that public key, and use it for
multiple incoming ciphertexts, generating multiple shared secret keys.  While
this is safe, it is recommended that if the protocol allows it (if Alice and
Bob exchange messages anyways) that Alice generates a fresh keypair each time
(and zeroize the private key immediately after) to obtain Perfect Forward
Secrecy. Be noted that generally key generation of ML-KEM is very fast, see
{{par-perf}}. That is, if Alice's system is subverted (either by a hacker or
a legal warrant), the previous communications remain secure (because Alice no
longer has the information needed to recover the shared secret keys).

Alice and Bob must perform the Key Check steps (the Encapsulation Key Check
on the public key for Bob, the Decapsulation Key Check on the ciphertext for
Alice).  The cryptographical libraries that Alice and Bob use may
automatically perform such checks; if so, that should be verified.

The shared secret key for all three parameter sets, ML-KEM-512, ML-KEM-768
and ML-KEM-1024 is 32 bytes which are indistinguishable from 32-byte
pseudorandom byte-strings of 128, 192 and 256 bits of strengths
respectively. As such, it is suitable both to use directly as a symmetric key
(for use by a symmetric cipher such as AES or a MAC), and for inserting into
a Key Derivation Function.  This is in contrast to a Diffie-Hellman (or ECDH)
operation, where the output is distinguishable from random.

It is essential that the public key is generated correctly when the initial
key generation is performed and expanded. Lattice public keys are a lattice
and a secret hidden by an error term; if additional error can be introduced
into the public key generation stage, then the success of decapsulation can
reveal enough of the secret that successive queries determine the private
key. Notably, this means a public key can be 'poisoned' such that a future
adversary can recover the private key even though it will appear correct in
normal usage.

Per the analysis of the final {{FIPS203}} in Sophie Schmieg’s [KEMMY24], a
strictly compliant instantiation of ML-KEM is LEAK-BIND-K-PK-secure and
LEAK-BIND-K-CT-secure when using the expanded key format, but not
MAL-BIND-K-PK-secure nor MAL-BIND-K-CT-secure. This means that the computed
shared secret binds to the encapsulation key used to compute it against a
malicious adversary that has access to leaked, honestly-generated key
material but is not capable of manufacturing maliciously generated
keypairs. This binding to the encapsulation key broadly protects against
re-encapsulation attacks but not completely.

Using the 64-byte seed format provides a step up in binding security by
mitigating an attack enabled by the hash of the public key stored in the
expanded private key format, providing MAL-BIND-K-CT security and
LEAK-BIND-K-PK security.

If you using the 64-byte seed format for key pairs in a higher protocol,
including the shared secret in the protocol KDF with the expanded public key
to also bind to the public ciphertext, as the shared secret is doing that for
you. If you can't enforce use of the 64-byte seed format everywhere, also
including the ciphertext in your protocol KDF can help enforce that the
protocol key material that is the image of the protocol KDF is independent
from every shared secret, public key, and ciphertext used, each time.

# Security Properties (#security-properties}

## IND-CCA2

The fundamental security property is that someone listening to the exchanges
(and thus obtains both the public key and the ciphertext) cannot reconstruct
the shared secret key and this is true even if the adversary has access to a
CRQC. ML-KEM is IND-CCA2 secure, that is, it remains secure even if an
adversary is able to submit arbitrary ciphertexts and observe the resulting
shared key. Submitting invalid ciphertexts to a ML-KEM.Decaps does not help
the attacker obtain information about the decryption key of the PKE-Decrypt
function inside the ML-KEM.Decaps. Substituting the public key Alice sends
Bob by another public key chosen by the attacker will not help the attacker
get any information about Alice's private key, it would just make Alice and
Bob not have a same shared secret key. However, if it is possible to
substitute the copy of the public key for both Alice and Bob, an attacker can
introduce a malicious public key where the same private key can be used for
decapsulation, but the probability of decryption failure is marginally
higher. As decryption failures can leak information about the secret
decapulation key, it is important that Alice keeps a secure copy of the
public key as part of her secret key. For practical purposes, IND-CCA2 means
that ML-KEM is secure to use with static public keys.

## Binding properties

ML-KEM is a Key Encapsulation Mechanism (KEM). One common misunderstanding of
that term is the expectation that Bob freely chooses the shared secret, and
encrypts that when sending to Alice. What happens in ML-KEM is that
randomness from both sides are used to contribute to the shared secret. That
is, ML-KEM internally generates the shared secret in a way that Bob cannot
select the value. Now, Bob can generate a number of ciphertext/shared secret
pairs, and select the shared secret that he prefers, but he cannot freely
choose it or make secrets shared with two parties be equal. This is different
from RSA-KEM {{RFC5990}}, where Bob cannot select the value, but can
encapsulate the same shared secret to many recipients.

The computational binding properties for KEMs were formalized in
{{CDM23}}. The binding properties of KEMs have implications for their use in
protocols and whether those protocols are resilient against re-encapsulation
attacks or how KEMs should be integrated into protocols to achieve strong
session independence properties, say.

Re-encapsulation attacks exploit the fact that some KEMs allow the
decapsulation of a ciphertext to an output key `k` and then can produce a
second ciphertext for a different public key that decapsulates to the same
`k`. Re-encapsulation attacks in protocols, often known as unknown-key-share
attacks, result in two parties computing the same key despite disagreeing on
their respective partners. This is completely allowed under the IND-CCA
security definition. To avoid these sorts of attacks, we need to know more
about a KEM than just that it’s an IND-CCA-secure KEM: we need to know how it
binds its shared secrets to encapsulation keys and ciphertexts. This is a
thing we didn’t need to think about with Diffie-Hellman, as it was only in
weird cases (small-order points, 'non-contributory behavior', etc) that
Diffie-Hellman public keys were not tightly bound to the shared secret
resulting from the computation, and there was no ciphertext to consider.

{{CDM23}} formalized these notions of 'binding properties for KEMs and
explored their relations to similar notions like 'robustness' and
'contributivity' in the literature, including describing a spectrum of
adversaries with different capabilities, how these notions relate (or imply)
each other. For a value to 'bind' another value, such as a shared secret K
binding an encapsulation key PK, is to uniquely determine it; more formally,
"P binds Q" if, for fixed instances of P, there are no collisions in the
instances of Q.

There are different security models of adversaries for these properties:
honest (HON), leak (LEAK), and malicious (MAL). Honest variants involve key
pairs that are correctly output by `KEM.KeyGen()` and not accessible by the
adversary, but the adversary has access to a `KEM.Decaps()` oracle. Leakage
variants have honestly-generated key pairs leaked to the adversary. In
malicious variants, the adversary can create the key pairs any way they like
in addition to the key generation, which is quite strong attacker model.

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}
