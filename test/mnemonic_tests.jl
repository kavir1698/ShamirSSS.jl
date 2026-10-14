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

@testset "secret string codec" begin
  # Regression: the old base-1000 codec corrupted code points >= 1000 and
  # dropped leading NUL bytes. The UTF-8/sentinel codec must be injective.
  for s in ("", "a", "hello world", "café", "😀", "ॐ", "emoji😀secret", "\0abc", "\0\0", "Ω≈ç√∫")
    @test ShamirSSS.number_to_string(ShamirSSS.string_to_number(s)) == s
  end

  # Distinct secrets must not collide.
  @test ShamirSSS.string_to_number("😀") != ShamirSSS.string_to_number("\u80Ȁ")
  @test ShamirSSS.string_to_number("\0abc") != ShamirSSS.string_to_number("abc")

  # Garbage values are rejected rather than silently decoded.
  @test_throws ArgumentError ShamirSSS.number_to_string(BigInt(0))
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

  t = 3
  set_id = (0x01, 0x02, 0x03, 0x04)
  mnemonic = ShamirSSS.share_to_mnemonic(share; t=t, set_id=set_id)
  @test occursin(' ', mnemonic)

  restored = ShamirSSS.mnemonic_to_share(mnemonic)
  @test restored.x.value == share[1].value
  @test restored.y.value == share[2].value
  @test restored.x.field.p == p
  @test restored.t == t
  @test restored.set_id == set_id
  @test restored.legacy == false
end

@testset "Mnemonic error detection" begin
  p = BigInt(104729)
  field = ShamirSSS.FiniteField(p)
  share = (
    ShamirSSS.FieldElement(BigInt(7), field),
    ShamirSSS.FieldElement(BigInt(99991), field),
  )
  words = split(ShamirSSS.share_to_mnemonic(share; t=2))

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

  # Wrong magic header.
  @test_throws ArgumentError ShamirSSS.bytes_to_share(vcat(UInt8[0x00, 0x00, 0x00, 0x00], zeros(UInt8, 12)))

  # Declared component length exceeds the buffer (previously a BoundsError).
  truncated = vcat(
    ShamirSSS.SHARE_MAGIC,
    UInt8[0x00, 0x00],          # t
    UInt8[0x00, 0x00, 0x00, 0x00],  # set_id
    UInt8[0x00, 0xff],          # xlen = 255, but no payload follows
  )
  @test_throws ArgumentError ShamirSSS.bytes_to_share(truncated)

  # A valid payload with an appended byte must be rejected as trailing data.
  p = BigInt(7)
  field = ShamirSSS.FiniteField(p)
  share = (ShamirSSS.FieldElement(BigInt(1), field), ShamirSSS.FieldElement(BigInt(1), field))
  payload = ShamirSSS.share_to_bytes(share; t=2)
  @test_throws ArgumentError ShamirSSS.bytes_to_share(vcat(payload, UInt8(0x00)))

  # A modulus of 1 is invalid.
  field_one = ShamirSSS.FiniteField(BigInt(1))
  share_one = (ShamirSSS.FieldElement(BigInt(1), field_one), ShamirSSS.FieldElement(BigInt(1), field_one))
  @test_throws ArgumentError ShamirSSS.bytes_to_share(ShamirSSS.share_to_bytes(share_one; t=2))

  # A composite modulus must be rejected by the primality check.
  field_composite = ShamirSSS.FiniteField(BigInt(9))
  share_composite = (ShamirSSS.FieldElement(BigInt(1), field_composite), ShamirSSS.FieldElement(BigInt(2), field_composite))
  @test_throws ArgumentError ShamirSSS.bytes_to_share(ShamirSSS.share_to_bytes(share_composite; t=2))

  # An oversized component is rejected before any expensive work.
  oversized = vcat(
    ShamirSSS.SHARE_MAGIC,
    UInt8[0x00, 0x02],          # t = 2
    UInt8[0x00, 0x00, 0x00, 0x00],
    UInt8[0xff, 0xff],          # xlen = 65535 > MAX_MODULUS_BYTES
    zeros(UInt8, 16),
  )
  @test_throws ArgumentError ShamirSSS.bytes_to_share(oversized)
end

@testset "Base64 share checksum" begin
  shares = ShamirSSS.split_secret("integrity matters", 3, 2; prime_bits=256, format=:base64)

  # A corrupted base64 payload must be rejected by the checksum.
  raw = ShamirSSS.base64decode(shares[1])
  raw[end] = xor(raw[end], 0x01)
  corrupted = ShamirSSS.base64encode(raw)
  @test_throws ArgumentError ShamirSSS.deserialize_share(corrupted)
end

@testset "Legacy (0.3.0) share compatibility" begin
  secret = "hello world"
  p = ShamirSSS.generate_prime(256)
  rng = ShamirSSS.RandomDevice()
  secret_number = ShamirSSS.legacy_string_to_number(secret)
  shares = ShamirSSS.generate_shares(rng, secret_number, 5, 3, p)

  # Legacy base64 payload: the decimal string "x,y,p".
  legacy_b64 = [ShamirSSS.base64encode("$(x.value),$(y.value),$(p)") for (x, y) in shares]
  @test all(s -> !occursin(' ', s), legacy_b64)
  @test ShamirSSS.reconstruct_secret(legacy_b64[[1, 2, 3]]) == secret

  # Legacy mnemonic payload: x, y, p with 2-byte length prefixes.
  function legacy_payload(share)
    x, y = share
    component(n) = begin
      b = ShamirSSS.number_to_bytes(n)
      vcat(UInt8(length(b) >> 8), UInt8(length(b) & 0xff), b)
    end
    return vcat(component(x.value), component(y.value), component(x.field.p))
  end
  legacy_mn = [join(ShamirSSS.bytes_to_mnemonic_words(legacy_payload(s)), " ") for s in shares]
  @test all(s -> occursin(' ', s), legacy_mn)
  @test ShamirSSS.reconstruct_secret(legacy_mn[[2, 3, 4]]) == secret

  # Legacy and current shares must not be mixed.
  current = ShamirSSS.split_secret(secret, 5, 3; prime_bits=256)
  @test_throws ArgumentError ShamirSSS.reconstruct_secret([legacy_mn[1], current[2], legacy_mn[3]])

  # A legacy base64 modulus larger than MAX_MODULUS_BITS must be rejected by the
  # bit-length cap (not merely by primality), even though its decimal length is
  # within MAX_MODULUS_DIGITS.
  oversized_p = BigInt(10)^2467 - 1
  @test ndigits(oversized_p, base=2) > ShamirSSS.MAX_MODULUS_BITS
  @test length(string(oversized_p)) <= ShamirSSS.MAX_MODULUS_DIGITS
  @test_throws ArgumentError ShamirSSS.deserialize_share(
    ShamirSSS.base64encode("1,2,$oversized_p"),
  )
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

@testset "split_secret / reconstruct_secret handle arbitrary Unicode" begin
  for secret in ("café", "emoji😀secret", "ॐ", "\0abc", "")
    shares = ShamirSSS.split_secret(secret, 4, 2; prime_bits=256, format=:mnemonic)
    @test ShamirSSS.reconstruct_secret(shares[[3, 1]]) == secret

    b64 = ShamirSSS.split_secret(secret, 4, 2; prime_bits=256, format=:base64)
    @test ShamirSSS.reconstruct_secret(b64[[2, 4]]) == secret
  end
end

@testset "reconstruct_secret rejects invalid share sets" begin
  # Too few shares.
  shares = ShamirSSS.split_secret("threshold secret", 5, 3; prime_bits=256)
  @test_throws ArgumentError ShamirSSS.reconstruct_secret(shares[[1, 2]])

  # Shares from different splits always use different moduli, so this trips the
  # modulus check rather than the set-id check.
  other = ShamirSSS.split_secret("threshold secret", 5, 3; prime_bits=256)
  @test_throws ArgumentError ShamirSSS.reconstruct_secret([shares[1], other[2], shares[3]])

  # Set-id rejection with a shared modulus: craft shares that agree on `p` and
  # `t` but carry different set identifiers.
  p = ShamirSSS.generate_prime(256)
  rng = ShamirSSS.RandomDevice()
  secret_number = ShamirSSS.string_to_number("threshold secret")
  raw = ShamirSSS.generate_shares(rng, secret_number, 5, 3, p)
  set_a = [ShamirSSS.serialize_share(s; t=3, set_id=(0x01, 0x02, 0x03, 0x04)) for s in raw]
  set_b = ShamirSSS.serialize_share(raw[2]; t=3, set_id=(0x05, 0x06, 0x07, 0x08))
  @test_throws ArgumentError ShamirSSS.reconstruct_secret([set_a[1], set_b, set_a[3]])

  # Duplicate shares must be rejected explicitly (not surfaced as a
  # division-by-zero during interpolation).
  @test_throws ArgumentError ShamirSSS.reconstruct_secret([shares[1], shares[1], shares[2], shares[3]])

  # Empty input.
  @test_throws ArgumentError ShamirSSS.reconstruct_secret(String[])
end

@testset "split_secret rejects invalid parameters" begin
  @test_throws ArgumentError ShamirSSS.split_secret("secret", 3, 2; prime_bits=256, format=:hex)
  @test_throws ArgumentError ShamirSSS.split_secret("secret", 3, 4; prime_bits=256)
  @test_throws ArgumentError ShamirSSS.split_secret("secret", 3, 1; prime_bits=256)
  @test_throws ArgumentError ShamirSSS.split_secret("secret", 0, 2; prime_bits=256)
  @test_throws ArgumentError ShamirSSS.split_secret("secret", 3, 2; prime_bits=ShamirSSS.MAX_MODULUS_BITS + 1)
end
