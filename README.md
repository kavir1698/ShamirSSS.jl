# ShamirSSS.jl

A Julia package implementing Shamir's Secret Sharing Scheme.

## Overview

Shamir's Secret Sharing Scheme is a cryptographic technique for securely sharing a secret among multiple parties. This package provides two primary functions:

* `split_secret`: splits a secret string into multiple shares, with a specified threshold required for reconstruction.
* `reconstruct_secret`: reconstructs the original secret string from a set of shares.

## Installation

To use this package, add the following line to your Julia REPL:
```julia
Pkg.add("ShamirSSS")
```

## Usage

### Splitting a Secret

To split a secret string into shares, use the `split_secret` function:

```julia
using ShamirSSS

secret = "my_secret_string"
n = 5  # number of shares
t = 3  # threshold required for reconstruction

shares = split_secret(secret, n, t)
```

This will generate a vector of `n` shares. By default each share is a
human-readable BIP-39-style mnemonic phrase, which is easier to write down and
transfer than raw bytes:

```julia
# e.g.
# "legal winner thank year wave sausage worth useful legal winner thank yellow" ...
```

Pass `format=:base64` to get the compact base64 encoding instead.

> Note: a share's mnemonic length scales with `prime_bits`, which defaults to
> `256`. The modulus only needs to be larger than the secret, so it is raised
> automatically for larger secrets; increasing it does not make the scheme more
> secure, it only makes the shares longer.

### Reconstructing a Secret

To reconstruct the original secret string from a set of shares, use the `reconstruct_secret` function:

```julia
reconstructed_secret = reconstruct_secret(shares[[5,2,3]])
```

This will return the original secret string.

## Parameters

* `secret`: the secret string to be split (required)
* `n`: the number of shares to generate (required)
* `t`: the minimum number of shares required to reconstruct the secret (required)
* `prime_bits`: the minimum number of bits for the prime modulus (optional, default: 256; raised automatically when the secret is larger)
* `format`: the share encoding, either `:mnemonic` (default) or `:base64` (optional)

## Returns

* `split_secret`: a vector of serialized share strings, in the requested format
* `reconstruct_secret`: the reconstructed secret string

`reconstruct_secret` auto-detects whether each supplied share is a mnemonic
phrase or a base64 string. The individual `share_to_mnemonic` and
`mnemonic_to_share` functions convert a single `(x, y)` share to and from a
mnemonic phrase.

## Security notes

Shamir's scheme provides **secrecy, but not authenticity**. This means:

* Any `t` (or more) correct shares reconstruct the secret exactly.
* Fewer than `t` shares reveal **nothing** about the secret.
* The scheme does **not** detect a deliberate forgery: an attacker who can
  modify shares can cause a wrong secret to be reconstructed.

The format mitigates the common *accidental* failure modes, but does not
replace authentication:

* Every share header stores the threshold `t`, so `reconstruct_secret` rejects
  a set that contains fewer than `t` shares instead of silently interpolating a
  garbage value.
* Every share from one `split_secret` call carries a random per-split
  identifier. Mixing shares from different splits is rejected before
  interpolation.
* Both share formats carry a SHA-256 checksum, so an accidentally corrupted
  share (mnemonic or base64) is rejected when decoded. The self-encoding used
  for the secret itself also rejects values that are not valid encodings.
* `bytes_to_share` / `mnemonic_to_share` verify that the share's modulus is
  prime, and the modulus size is bounded to keep decoding of untrusted input
  cheap.
* Shares produced by version 0.3.0 and earlier are still decoded on a
  best-effort basis, but they carry no threshold or set information and their
  legacy secret encoding cannot represent non-Latin1 characters.

If you need to detect tampering, authenticate the shares independently (for
example, sign them or distribute them over an authenticated channel), and verify
the reconstructed secret against a known value you trust.

The secret is encoded as its raw UTF-8 bytes, so any Unicode string, including
one with leading NUL bytes or astral-plane characters, round-trips exactly.

## Example Use Cases

* Securely sharing a password among multiple team members
* Distributing a cryptographic key among multiple servers
* Creating a backup of sensitive data using multiple shares
