using ShamirSSS
using Test

function example()
  secret = secure_rand(rng, BigInt(2)^256)

  # Calculate the number of bits needed for the prime
  secret_bits = ndigits(secret, base=2)
  prime_bits = max(secret_bits + 128, 1024) # ensure p > secret and at least 512 bytes (4096 bits). Here only for testing we are using 1024 bits

  @test secret_bits <= prime_bits - 128

  # Generate a random prime p with prime_bits using Primes.jl
  p = generate_safe_prime(prime_bits)

  n = 5  # Total number of shares
  t = 3  # Threshold (minimum number of shares needed to reconstruct)

  # Create a cryptographically secure RNG
  rng = RandomDevice()

  # Generate shares
  shares = generate_shares(rng, secret, n, t, p)

  # Serialize and deserialize a share
  serialized_share = serialize_share(shares[1])
  deserialized_share = deserialize_share(serialized_share)
  @test shares[1][2].value == deserialized_share[2].value

  reconstructed_secret = reconstruct_secret_num(shares)
  @test reconstructed_secret.value == secret

  # Reconstruct secret using only t shares
  subset_shares = shares[1:t]
  reconstructed_secret_subset = reconstruct_secret_num(subset_shares)
  @test reconstructed_secret_subset.value == secret
end

example()
