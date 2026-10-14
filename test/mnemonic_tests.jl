@testset "BIP-39 wordlist" begin
  @test length(ShamirSSS.BIP39_WORDLIST) == 2048
  @test allunique(ShamirSSS.BIP39_WORDLIST)
  @test ShamirSSS.BIP39_WORD_INDEX["abandon"] == 0
  @test ShamirSSS.BIP39_WORD_INDEX["zoo"] == 2047
end

@testset "number_to_bytes / bytes_to_number" begin
  for n in (BigInt(0), BigInt(1), BigInt(255), BigInt(256), BigInt(2)^256 - 1, BigInt(2)^4096 - 1)
    @test ShamirSSS.bytes_to_number(ShamirSSS.number_to_bytes(n)) == n
  end
end

@testset "bytes <-> mnemonic word codec" begin
  rng = ShamirSSS.MersenneTwister(2024)
  for n in (1, 2, 3, 5, 11, 16, 32, 33, 64)
    payload = rand(rng, UInt8, n)
    words = ShamirSSS.bytes_to_mnemonic_words(payload)
    @test all(w -> haskey(ShamirSSS.BIP39_WORD_INDEX, w), words)
    @test ShamirSSS.mnemonic_words_to_bytes(words) == payload
  end
end

@testset "Share mnemonic round-trip" begin
  p = BigInt(104729)
  field = ShamirSSS.FiniteField(p)
  share = (
    ShamirSSS.FieldElement(BigInt(3), field),
    ShamirSSS.FieldElement(BigInt(12345), field),
  )

  mnemonic = ShamirSSS.share_to_mnemonic(share)
  @test occursin(' ', mnemonic)

  restored = ShamirSSS.mnemonic_to_share(mnemonic)
  @test restored[1].value == share[1].value
  @test restored[2].value == share[2].value
  @test restored[1].field.p == p
end

@testset "Mnemonic error detection" begin
  p = BigInt(104729)
  field = ShamirSSS.FiniteField(p)
  share = (
    ShamirSSS.FieldElement(BigInt(7), field),
    ShamirSSS.FieldElement(BigInt(99991), field),
  )
  words = split(ShamirSSS.share_to_mnemonic(share))

  # A single corrupted word must be rejected by the checksum.
  for idx in (1, length(words))
    broken = copy(words)
    broken[idx] = broken[idx] == "abandon" ? "ability" : "abandon"
    @test_throws ArgumentError ShamirSSS.mnemonic_to_share(join(broken, " "))
  end

  @test_throws ArgumentError ShamirSSS.mnemonic_to_share("abandon notaword zoo")
  @test_throws ArgumentError ShamirSSS.mnemonic_to_share("")
  @test_throws ArgumentError ShamirSSS.mnemonic_to_share("abandon")

  # Extra trailing words are non-canonical and must be rejected.
  @test_throws ArgumentError ShamirSSS.mnemonic_to_share(join(words) * " abandon")
  @test_throws ArgumentError ShamirSSS.mnemonic_to_share("abandon " * join(words))
end

@testset "Malformed share payload validation" begin
  @test_throws ArgumentError ShamirSSS.bytes_to_share(UInt8[])

  # Declared component length exceeds the buffer (previously a BoundsError).
  truncated = UInt8[0x00, 0xff, 0x01, 0x00, 0x01, 0x00]
  @test_throws ArgumentError ShamirSSS.bytes_to_share(truncated)

  # A valid payload with an appended byte must be rejected as trailing data.
  p = BigInt(7)
  field = ShamirSSS.FiniteField(p)
  share = (ShamirSSS.FieldElement(BigInt(1), field), ShamirSSS.FieldElement(BigInt(1), field))
  payload = ShamirSSS.share_to_bytes(share)
  @test_throws ArgumentError ShamirSSS.bytes_to_share(vcat(payload, UInt8(0x00)))

  # A modulus of 1 is invalid.
  invalid_modulus = UInt8[0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01]
  @test_throws ArgumentError ShamirSSS.bytes_to_share(invalid_modulus)
end

@testset "split_secret / reconstruct_secret with mnemonics" begin
  secret = "hello world"
  shares = ShamirSSS.split_secret(secret, 5, 3; prime_bits=256, format=:mnemonic)

  @test length(shares) == 5
  @test all(s -> occursin(' ', s), shares)

  @test ShamirSSS.reconstruct_secret(shares[[5, 2, 3]]) == secret

  default_shares = ShamirSSS.split_secret(secret, 5, 3; prime_bits=256)
  @test all(s -> occursin(' ', s), default_shares)
  @test ShamirSSS.reconstruct_secret(default_shares[[2, 3, 4]]) == secret

  base64_shares = ShamirSSS.split_secret(secret, 5, 3; prime_bits=256, format=:base64)
  @test all(s -> !occursin(' ', s), base64_shares)
  @test ShamirSSS.reconstruct_secret(base64_shares[[1, 4, 5]]) == secret
end

@testset "split_secret rejects unknown format" begin
  @test_throws ArgumentError ShamirSSS.split_secret("secret", 3, 2; prime_bits=256, format=:hex)
end
