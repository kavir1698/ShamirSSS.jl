"""
    split_secret(secret::String, n::Int, t::Int; prime_bits::Int=256, format::Symbol=:mnemonic)::Vector{String}

Split a secret string into n shares, with a threshold of t shares required for reconstruction.

Parameters:
- secret: The secret string to be split
- n: The total number of shares to generate
- t: The minimum number of shares required to reconstruct the secret
- prime_bits: The minimum number of bits for the prime modulus (default: 256).
  The modulus only needs to be larger than the secret, so this is raised
  automatically when the secret is larger; a larger value is not more secure.
- format: The output share format, either `:mnemonic` (default) for
  BIP-39-style word phrases that are easier to transcribe and transfer, or
  `:base64`

Returns:
- A vector of serialized share strings

Every share records the threshold `t` and a random per-split identifier in its
header, so [`reconstruct_secret`](@ref) can reject too-few or mismatched share
sets instead of silently returning a corrupted secret.
"""
function split_secret(secret::String, n::Int, t::Int; prime_bits::Int=256, format::Symbol=:mnemonic)::Vector{String}
  t >= 2 || throw(ArgumentError("Threshold t must be at least 2"))
  t <= n || throw(ArgumentError("Threshold t must be less than or equal to the number of shares n"))
  prime_bits >= 2 || throw(ArgumentError("prime_bits must be at least 2"))
  (format === :mnemonic || format === :base64) ||
    throw(ArgumentError("Unsupported share format: $format (expected :base64 or :mnemonic)"))

  secret_number = string_to_number(secret)
  secret_bits = ndigits(secret_number, base=2)
  prime_bits = max(secret_bits + 128, prime_bits)
  prime_bits <= MAX_MODULUS_BITS ||
    throw(ArgumentError("Secret is too large: modulus would need $prime_bits bits (maximum $MAX_MODULUS_BITS)"))

  p = generate_prime(prime_bits)
  secret_number < p || throw(ArgumentError("Secret is too large for the given prime size"))

  rng = RandomDevice()
  set_id = Tuple(rand(rng, UInt8, 4))
  shares = generate_shares(rng, secret_number, n, t, p)

  if format === :mnemonic
    return [share_to_mnemonic(share; t=t, set_id=set_id) for share in shares]
  else
    return [serialize_share(share; t=t, set_id=set_id) for share in shares]
  end
end

"""
    reconstruct_secret(shares::Vector{String})::String

Reconstruct the secret string from a set of shares.

Parameters:
- shares: A vector of serialized share strings, in either base64 or mnemonic
  format (the format is detected automatically)

Returns:
- The reconstructed secret string

Throws an `ArgumentError` if the shares come from different splits, disagree on
the threshold, fewer than `t` shares are supplied, or the decoded value is not a
valid encoding. Shares produced by version 0.3.0 and earlier are still decoded
on a best-effort basis, but they carry no threshold or set information.

Note: Shamir's scheme provides no authenticity. The per-share checksums only
detect accidental corruption, and the header checks above only catch
inconsistent share sets. They do not authenticate shares against a deliberate
forgery.
"""
function reconstruct_secret(shares::Vector{String})::String
  isempty(shares) && throw(ArgumentError("At least one share is required to reconstruct the secret"))

  parsed = [deserialize_any_share(share) for share in shares]

  p = parsed[1].x.field.p
  legacy = parsed[1].legacy
  for s in parsed
    s.x.field.p == p || throw(ArgumentError("All shares must use the same prime modulus"))
    s.legacy == legacy || throw(ArgumentError("Cannot mix legacy and current shares"))
  end

  # Duplicate shares would otherwise satisfy the count check below and then
  # surface as a division-by-zero during interpolation.
  distinct = Set(s.x.value for s in parsed)
  length(distinct) == length(parsed) ||
    throw(ArgumentError("Duplicate shares are not allowed"))

  if !legacy
    t = parsed[1].t
    t >= 2 || throw(ArgumentError("Shares carry an invalid threshold"))
    set_id = parsed[1].set_id
    for s in parsed
      s.t == t || throw(ArgumentError("All shares must have the same threshold"))
      s.set_id == set_id || throw(ArgumentError("Shares do not belong to the same secret set"))
    end
    # Reject obviously insufficient share counts before interpolating.
    length(parsed) >= t ||
      throw(ArgumentError("At least $t shares are required to reconstruct the secret"))
  end

  field = FiniteField(p)
  unified_shares = [(FieldElement(s.x.value, field), FieldElement(s.y.value, field)) for s in parsed]
  reconstructed = lagrange_interpolation(unified_shares, FieldElement(BigInt(0), field))

  return legacy ? legacy_number_to_string(reconstructed.value) : number_to_string(reconstructed.value)
end

function deserialize_any_share(share::String)
  return occursin(' ', share) ? mnemonic_to_share(share) : deserialize_share(share)
end
