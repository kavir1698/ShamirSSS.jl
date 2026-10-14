struct FiniteField
  p::BigInt
end

struct FieldElement
  value::BigInt
  field::FiniteField
end

Base.:(==)(a::FiniteField, b::FiniteField) = a.p == b.p

# Upper bound on the modulus accepted when decoding a share. It bounds the cost
# of the primality test on attacker-supplied input (a denial-of-service guard)
# and is enforced symmetrically when splitting a secret.
const MAX_MODULUS_BITS = 8192
const MAX_MODULUS_BYTES = cld(MAX_MODULUS_BITS, 8)
# Decimal-digit bound for the legacy base64 path; derived from the bit cap so a
# decimal string cannot admit a modulus larger than MAX_MODULUS_BITS.
const MAX_MODULUS_DIGITS = ndigits(BigInt(2)^MAX_MODULUS_BITS)
const SHARE_CHECKSUM_BYTES = 4

"""
    Share

A decoded share together with the metadata needed to safely reconstruct a
secret:

- `x`, `y`: the share's coordinates in the finite field.
- `t`: the threshold (minimum number of shares) this share was generated with.
- `set_id`: a random identifier shared by every share from the same split. It
  lets `reconstruct_secret` reject shares that come from different splits
  before interpolating.
- `legacy`: `true` when the share was decoded from the pre-0.4.0 format, which
  carries no threshold or set metadata.
"""
struct Share
  x::FieldElement
  y::FieldElement
  t::Int
  set_id::NTuple{4,UInt8}
  legacy::Bool
end

# Big-endian byte <-> non-negative integer helpers, shared by all encodings.
function number_to_bytes(n::BigInt)::Vector{UInt8}
  n < 0 && throw(ArgumentError("Cannot encode a negative number"))
  n == 0 && return UInt8[0x00]
  bytes = UInt8[]
  while n > 0
    push!(bytes, UInt8(n & 0xff))
    n >>= 8
  end
  return reverse(bytes)
end

function bytes_to_number(bytes::AbstractVector{UInt8})::BigInt
  n = BigInt(0)
  for b in bytes
    n = (n << 8) | b
  end
  return n
end

# Finite field operations
function ⊕(a::FieldElement, b::FieldElement)
  a.field == b.field || throw(ArgumentError("Elements must be in the same field"))
  return FieldElement(mod(a.value + b.value, a.field.p), a.field)
end

function ⊖(a::FieldElement, b::FieldElement)
  a.field == b.field || throw(ArgumentError("Elements must be in the same field"))
  return FieldElement(mod(a.value - b.value + a.field.p, a.field.p), a.field)
end

function ⊗(a::FieldElement, b::FieldElement)
  a.field == b.field || throw(ArgumentError("Elements must be in the same field"))
  return FieldElement(mod(a.value * b.value, a.field.p), a.field)
end

function inv_mod(a::BigInt, m::BigInt)
  m > 1 || throw(DomainError(m, "Modulus must be greater than 1"))

  t, new_t = BigInt(0), BigInt(1)
  r, new_r = m, mod(a, m)

  while new_r != 0
    quotient = r ÷ new_r
    t, new_t = new_t, t - quotient * new_t
    r, new_r = new_r, r - quotient * new_r
  end

  r == 1 || throw(DomainError(a, "Value is not invertible modulo $m"))
  if t < 0
    t += m
  end
  return t
end

function /(a::FieldElement, b::FieldElement)
  a.field == b.field || throw(ArgumentError("Elements must be in the same field"))
  b.value != 0 || throw(DomainError(b.value, "Division by zero"))
  inverse = inv_mod(b.value, a.field.p)
  return FieldElement(mod(a.value * inverse, a.field.p), a.field)
end

function Base.:(==)(a::FieldElement, b::FieldElement)
  return a.value == b.value && a.field.p == b.field.p
end

# Cryptographically secure random number generation
function secure_rand(rng::AbstractRNG, max::BigInt)
  max > 0 || throw(ArgumentError("max must be positive"))
  max == 1 && return BigInt(0)

  # Number of bits in [0, max-1]; reject values outside [0, max) to avoid bias.
  bytes_needed = cld(ndigits(max - 1, base=2), 8)

  while true
    value = bytes_to_number(rand(rng, UInt8, bytes_needed))
    if value < max
      return value
    end
  end
end

# Generate a random polynomial of degree t-1
function generate_polynomial(rng::AbstractRNG, secret::FieldElement, t::Int)
  coeffs = [secret]
  for _ in 1:t-1
    push!(coeffs, FieldElement(secure_rand(rng, secret.field.p), secret.field))
  end
  return coeffs
end

# Evaluate the polynomial at point x
function evaluate_polynomial(coeffs::Vector{FieldElement}, x::FieldElement)
  result = coeffs[1]
  power = FieldElement(BigInt(1), x.field)
  for i in 2:length(coeffs)
    power = power ⊗ x
    term = coeffs[i] ⊗ power
    result = result ⊕ term
  end
  return result
end

# Generate shares
function generate_shares(rng::AbstractRNG, secret::BigInt, n::Int, t::Int, p::BigInt)
  t >= 2 || throw(ArgumentError("Threshold t must be at least 2"))
  t <= n || throw(ArgumentError("Threshold t must be less than or equal to the number of shares n"))
  secret < p || throw(ArgumentError("Secret must be smaller than the prime modulus"))
  isprime(p) || throw(ArgumentError("Modulus must be prime"))
  p > max(256, n) || throw(ArgumentError("Prime modulus too small for security"))

  field = FiniteField(p)
  secret_elem = FieldElement(secret, field)
  coeffs = generate_polynomial(rng, secret_elem, t)
  shares = Vector{Tuple{FieldElement,FieldElement}}(undef, n)

  for i in 1:n
    # Start from x=1 to avoid x=0 which would reveal the secret
    x = FieldElement(BigInt(i), field)
    y = evaluate_polynomial(coeffs, x)
    shares[i] = (x, y)
  end

  return shares
end

# Lagrange interpolation
function lagrange_interpolation(shares::Vector{Tuple{FieldElement,FieldElement}}, x::FieldElement)
  field = x.field
  result = FieldElement(BigInt(0), field)
  for (i, (xi, yi)) in enumerate(shares)
    numerator = FieldElement(BigInt(1), field)
    denominator = FieldElement(BigInt(1), field)
    for (j, (xj, _)) in enumerate(shares)
      if i != j
        numerator = numerator ⊗ (x ⊖ xj)
        denominator = denominator ⊗ (xi ⊖ xj)
      end
    end
    term = yi ⊗ (numerator / denominator)
    result = result ⊕ term
  end
  return result
end

# Reconstruct the secret
function reconstruct_secret_num(shares::Vector{Tuple{FieldElement,FieldElement}})
  isempty(shares) && throw(ArgumentError("At least one share is required"))
  return lagrange_interpolation(shares, FieldElement(BigInt(0), shares[1][1].field))
end

function generate_prime(bits::Int)
  bits >= 2 || throw(ArgumentError("Prime size must be at least 2 bits"))
  return nextprime(rand(BigInt(2)^(bits-1):BigInt(2)^bits-1))
end

# Validation shared by every decode path. Extracted so the base64, mnemonic,
# and legacy decoders cannot drift. The modulus size is bounded before the
# primality test so untrusted input cannot force unbounded BigInt work.
#
# A single-entry cache remembers the last modulus proven prime. Reconstruction
# decodes many shares of the same modulus back to back, so this avoids repeating
# an identical (and potentially slow) primality test per share. The cache only
# ever holds a value that already passed `isprime`, so a hit is always sound.
const _LAST_VALIDATED_MODULUS = Ref{BigInt}(BigInt(0))
const _LAST_VALIDATED_MODULUS_LOCK = ReentrantLock()

function validated_field(p::BigInt)
  p > 1 || throw(ArgumentError("Invalid modulus in share payload"))
  ndigits(p, base=2) <= MAX_MODULUS_BITS ||
    throw(ArgumentError("Modulus too large in share payload"))

  if _LAST_VALIDATED_MODULUS[] != p
    isprime(p) || throw(ArgumentError("Modulus in share payload must be prime"))
    lock(_LAST_VALIDATED_MODULUS_LOCK) do
      _LAST_VALIDATED_MODULUS[] = p
    end
  end
  return FiniteField(p)
end

# Single source of truth for detecting the current share format.
function has_share_magic(data::AbstractVector{UInt8})::Bool
  return length(data) >= length(SHARE_MAGIC) && data[1:length(SHARE_MAGIC)] == SHARE_MAGIC
end

# Binary share serialization (shared by the base64 and mnemonic formats).
# Layout: "SSS1" magic | t (2 bytes) | set_id (4 bytes) | x, y, p, each as a
# 2-byte big-endian length plus bytes.
const SHARE_MAGIC = UInt8[0x53, 0x53, 0x53, 0x31]  # "SSS1"
const SHARE_DEFAULT_SET_ID = (0x00, 0x00, 0x00, 0x00)

function share_to_bytes(
  share::Tuple{FieldElement,FieldElement};
  t::Integer,
  set_id::NTuple{4,UInt8}=SHARE_DEFAULT_SET_ID,
)::Vector{UInt8}
  2 <= t <= typemax(UInt16) ||
    throw(ArgumentError("Threshold t must be between 2 and $(typemax(UInt16))"))

  x, y = share
  components = (number_to_bytes(x.value), number_to_bytes(y.value), number_to_bytes(x.field.p))
  for component in components
    length(component) <= MAX_MODULUS_BYTES ||
      throw(ArgumentError("Share component too large for encoding"))
  end

  buf = copy(SHARE_MAGIC)
  push!(buf, UInt8(t >> 8), UInt8(t & 0xff))
  append!(buf, set_id)
  for component in components
    push!(buf, UInt8(length(component) >> 8), UInt8(length(component) & 0xff))
    append!(buf, component)
  end
  return buf
end

function read_share_component(data::AbstractVector{UInt8}, pos::Int)
  pos + 1 <= length(data) || throw(ArgumentError("Malformed share payload"))
  len = (Int(data[pos]) << 8) | Int(data[pos+1])
  # Bound the component size so a crafted share cannot force expensive BigInt
  # work (including the modulus primality test) on attacker-controlled input.
  len <= MAX_MODULUS_BYTES || throw(ArgumentError("Share component too large"))
  start = pos + 2
  start + len - 1 <= length(data) || throw(ArgumentError("Malformed share payload"))
  return data[start:start+len-1], start + len
end

function parse_current_share(data::AbstractVector{UInt8})::Share
  length(data) >= length(SHARE_MAGIC) + 2 + 4 || throw(ArgumentError("Malformed share payload"))
  pos = length(SHARE_MAGIC) + 1
  t = (Int(data[pos]) << 8) | Int(data[pos+1]); pos += 2
  set_id = Tuple(data[pos:pos+3]); pos += 4

  xb, pos = read_share_component(data, pos)
  yb, pos = read_share_component(data, pos)
  pb, pos = read_share_component(data, pos)
  pos - 1 == length(data) || throw(ArgumentError("Trailing bytes in share payload"))

  field = validated_field(bytes_to_number(pb))
  return Share(
    FieldElement(bytes_to_number(xb), field),
    FieldElement(bytes_to_number(yb), field),
    t,
    set_id,
    false,
  )
end

# Pre-0.4.0 mnemonic payload: x, y, p with 2-byte length prefixes, no header.
function parse_legacy_binary_share(data::AbstractVector{UInt8})::Share
  pos = 1
  xb, pos = read_share_component(data, pos)
  yb, pos = read_share_component(data, pos)
  pb, pos = read_share_component(data, pos)
  pos - 1 == length(data) || throw(ArgumentError("Trailing bytes in share payload"))

  field = validated_field(bytes_to_number(pb))
  return Share(
    FieldElement(bytes_to_number(xb), field),
    FieldElement(bytes_to_number(yb), field),
    0,
    SHARE_DEFAULT_SET_ID,
    true,
  )
end

function bytes_to_share(data::AbstractVector{UInt8})::Share
  if has_share_magic(data)
    return parse_current_share(data)
  end
  return parse_legacy_binary_share(data)
end

# Pre-0.4.0 base64 payload: the decimal string "x,y,p".
function parse_legacy_base64_share(decoded::AbstractVector{UInt8})::Share
  parts = split(String(decoded), ",")
  length(parts) == 3 || throw(ArgumentError("Malformed share payload"))
  all(part -> length(part) <= MAX_MODULUS_DIGITS, parts) ||
    throw(ArgumentError("Share component too large"))

  x = tryparse(BigInt, parts[1])
  y = tryparse(BigInt, parts[2])
  p = tryparse(BigInt, parts[3])
  (x === nothing || y === nothing || p === nothing) &&
    throw(ArgumentError("Malformed share payload"))

  field = validated_field(p)
  return Share(
    FieldElement(mod(x, p), field),
    FieldElement(mod(y, p), field),
    0,
    SHARE_DEFAULT_SET_ID,
    true,
  )
end

function serialize_share(
  share::Tuple{FieldElement,FieldElement};
  t::Integer,
  set_id::NTuple{4,UInt8}=SHARE_DEFAULT_SET_ID,
)
  payload = share_to_bytes(share; t=t, set_id=set_id)
  return base64encode(vcat(payload, sha256(payload)[1:SHARE_CHECKSUM_BYTES]))
end

function deserialize_share(serialized::String)
  decoded = base64decode(serialized)
  if has_share_magic(decoded)
    length(decoded) >= SHARE_CHECKSUM_BYTES + length(SHARE_MAGIC) ||
      throw(ArgumentError("Malformed share payload"))
    payload = decoded[1:end-SHARE_CHECKSUM_BYTES]
    stored = decoded[end-SHARE_CHECKSUM_BYTES+1:end]
    stored == sha256(payload)[1:SHARE_CHECKSUM_BYTES] ||
      throw(ArgumentError("Share checksum mismatch"))
    return parse_current_share(payload)
  end
  return parse_legacy_base64_share(decoded)
end
