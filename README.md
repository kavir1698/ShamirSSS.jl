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

> Note: a share's mnemonic length scales with `prime_bits`. The default 4096-bit
> modulus produces very long phrases; use a smaller modulus (for example
> `prime_bits=256`) when you want short, easily transferable shares. The
> modulus only needs to be larger than the secret.

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
* `prime_bits`: the number of bits for the prime modulus (optional, default: 4096)
* `format`: the share encoding, either `:mnemonic` (default) or `:base64` (optional)

## Returns

* `split_secret`: a vector of serialized share strings, in the requested format
* `reconstruct_secret`: the reconstructed secret string

`reconstruct_secret` auto-detects whether each supplied share is a mnemonic
phrase or a base64 string. The individual `share_to_mnemonic` and
`mnemonic_to_share` functions convert a single `(x, y)` share to and from a
mnemonic phrase; the mnemonic includes a checksum, so a mistyped word is
rejected on decoding.

## Example Use Cases

* Securely sharing a password among multiple team members
* Distributing a cryptographic key among multiple servers
* Creating a backup of sensitive data using multiple shares
