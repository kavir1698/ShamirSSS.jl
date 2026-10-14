"""
    split_secret(secret::String, n::Int, t::Int; prime_bits::Int=4096, format::Symbol=:mnemonic)::Vector{String}

Split a secret string into n shares, with a threshold of t shares required for reconstruction.

Parameters:
- secret: The secret string to be split
- n: The total number of shares to generate
- t: The minimum number of shares required to reconstruct the secret
- prime_bits: The number of bits for the prime modulus (default: 4096)
- format: The output share format, either `:mnemonic` (default) for
  BIP-39-style word phrases that are easier to transcribe and transfer, or
  `:base64`

Returns:
- A vector of serialized share strings
"""
function split_secret(secret::String, n::Int, t::Int; prime_bits::Int=4096, format::Symbol=:mnemonic)::Vector{String}
  @assert t >= 2 "Threshold t must be at least 2"
  @assert t <= n "Threshold t must be less than or equal to the number of shares n"

  secret_number = string_to_number(secret)
  secret_bits = ndigits(secret_number, base=2)
  prime_bits = max(secret_bits + 128, prime_bits)

  # @info "Generating a safe prime number ..."
  # p = generate_safe_prime(prime_bits) # not necessary for SSSS
  p = generate_prime(prime_bits)
  @assert secret_number < p "Secret is too large for the given prime size"

  rng = RandomDevice()
  shares = generate_shares(rng, secret_number, n, t, p)

  if format === :mnemonic
    return [share_to_mnemonic(share) for share in shares]
  elseif format === :base64
    return [serialize_share(share) for share in shares]
  else
    throw(ArgumentError("Unsupported share format: $format (expected :base64 or :mnemonic)"))
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
"""
function reconstruct_secret(shares::Vector{String})::String
  deserialized_shares = [deserialize_any_share(share) for share in shares]

  p = deserialized_shares[1][1].field.p

  # Ensure all shares use the same prime modulus
  for (x, y) in deserialized_shares
    @assert x.field.p == p && y.field.p == p "All shares must use the same prime modulus"
  end

  field = FiniteField(p)

  # Convert all shares to use the common field
  unified_shares = [(FieldElement(x.value, field), FieldElement(y.value, field)) for (x, y) in deserialized_shares]

  reconstructed_secret = lagrange_interpolation(unified_shares, FieldElement(BigInt(0), field))
  return number_to_string(reconstructed_secret.value)
end

function deserialize_any_share(share::String)
  return occursin(' ', share) ? mnemonic_to_share(share) : deserialize_share(share)
end
