@testset "Main tests" begin
  function example()
    rng = ShamirSSS.RandomDevice()
    secret = ShamirSSS.secure_rand(rng, BigInt(2)^256)

    # Calculate the number of bits needed for the prime
    secret_bits = ndigits(secret, base=2)
    prime_bits = max(secret_bits + 128, 1024) # ensure p > secret and at least 512 bytes (4096 bits). Here only for testing we are using 1024 bits

    @test secret_bits <= prime_bits - 128

    # Generate a random prime
    p = ShamirSSS.generate_safe_prime(prime_bits)

    n = 5  # Total number of shares
    t = 3  # Threshold (minimum number of shares needed to reconstruct)

    # Create a cryptographically secure RNG
    rng = ShamirSSS.RandomDevice()

    # Generate shares
    shares = ShamirSSS.generate_shares(rng, secret, n, t, p)

    # Serialize and deserialize a share
    serialized_share = ShamirSSS.serialize_share(shares[1])
    deserialized_share = ShamirSSS.deserialize_share(serialized_share)
    @test shares[1][2].value == deserialized_share[2].value

    reconstructed_secret = ShamirSSS.reconstruct_secret_num(shares)
    @test reconstructed_secret.value == secret

    # Reconstruct secret using only t shares
    subset_shares = shares[1:t]
    reconstructed_secret_subset = ShamirSSS.reconstruct_secret_num(subset_shares)
    @test reconstructed_secret_subset.value == secret
  end
  example()
end
