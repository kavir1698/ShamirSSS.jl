# ShamirSSS.jl

A Julia package implementing Shamir's Secret Sharing Scheme.

## Overview

Shamir's Secret Sharing Scheme is a cryptographic technique for securely sharing a secret among multiple parties. This package provides two primary functions:

* `split_secret`: splits a secret string into multiple shares, with a specified threshold required for reconstruction.
* `reconstruct_secret`: reconstructs the original secret string from a set of shares.

## Installation

To use this package, add the following line to your Julia REPL:
```julia
Pkg.add("https://github.com/kavir1698/ShamirSSS.jl.git")
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

This will generate a vector of `n` shares, each represented as a serialized string.

### Reconstructing a Secret

To reconstruct the original secret string from a set of shares, use the `reconstruct_secret` function:

```julia
reconstructed_secret = reconstruct_secret(shares)
```

This will return the original secret string.

## Parameters

* `secret`: the secret string to be split (required)
* `n`: the number of shares to generate (required)
* `t`: the minimum number of shares required to reconstruct the secret (required)
* `prime_bits`: the number of bits for the prime modulus (optional, default: 4096)

## Returns

* `split_secret`: a vector of serialized share strings
* `reconstruct_secret`: the reconstructed secret string

## Example Use Cases

* Securely sharing a password among multiple team members
* Distributing a cryptographic key among multiple servers
* Creating a backup of sensitive data using multiple shares
