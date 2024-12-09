struct FiniteField
  p::BigInt
end

struct FieldElement
  value::BigInt
  field::FiniteField
end

# Finite field operations
function ⊕(a::FieldElement, b::FieldElement)
  @assert a.field == b.field "Elements must be in the same field"
  return FieldElement(mod(a.value + b.value, a.field.p), a.field)
end

function ⊖(a::FieldElement, b::FieldElement)
  @assert a.field == b.field "Elements must be in the same field"
  return FieldElement(mod(a.value - b.value + a.field.p, a.field.p), a.field)
end

function ⊗(a::FieldElement, b::FieldElement)
  @assert a.field == b.field "Elements must be in the same field"
  return FieldElement(mod(a.value * b.value, a.field.p), a.field)
end

function inv_mod(a::BigInt, m::BigInt)
  t, new_t = BigInt(0), BigInt(1)
  r, new_r = m, a

  while new_r != 0
    quotient = r ÷ new_r
    t, new_t = new_t, t - quotient * new_t
    r, new_r = new_r, r - quotient * new_r
  end

  if r > 1
    error("Value is not invertible in the given field")
  end
  if t < 0
    t += m
  end
  return t
end

function /(a::FieldElement, b::FieldElement)
  @assert a.field == b.field "Elements must be in the same field"
  @assert b.value != 0 "Division by zero"
  inverse = inv_mod(b.value, a.field.p)
  return FieldElement(mod(a.value * inverse, a.field.p), a.field)
end

function Base.:(==)(a::FieldElement, b::FieldElement)
  return a.value == b.value && a.field.p == b.field.p
end

# Cryptographically secure random number generation
function secure_rand(rng::AbstractRNG, max::BigInt)
  bytes_needed = ceil(Int, log2(max)) + 1
  random_bytes = rand(rng, UInt8, bytes_needed)
  return mod(parse(BigInt, bytes2hex(random_bytes), base=16), max)
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
  @assert t <= n "Threshold t must be less than or equal to the number of shares n"
  @assert t >= 2 "Threshold t must be at least 2"
  @assert secret < p "Secret must be smaller than the prime modulus"

  field = FiniteField(p)
  secret_elem = FieldElement(secret, field)
  coeffs = generate_polynomial(rng, secret_elem, t)
  shares = Vector{Tuple{FieldElement,FieldElement}}(undef, n)

  for i in 1:n
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
  return lagrange_interpolation(shares, FieldElement(BigInt(0), shares[1][1].field))
end

function generate_safe_prime(bits::Int)
  while true
    p = nextprime(rand(BigInt(2)^(bits-1):BigInt(2)^bits-1))
    if isprime((p - 1) ÷ 2)
      return p
    end
  end
end
function generate_prime(bits::Int)
  return nextprime(rand(BigInt(2)^(bits-1):BigInt(2)^bits-1))
end

function serialize_share(share::Tuple{FieldElement,FieldElement})
  x, y = share
  return base64encode("$(x.value),$(y.value),$(x.field.p)")
end

function deserialize_share(serialized::String)
  decoded = String(base64decode(serialized))
  x_val, y_val, p = split(decoded, ",")
  field = FiniteField(parse(BigInt, p))
  x = FieldElement(parse(BigInt, x_val), field)
  y = FieldElement(parse(BigInt, y_val), field)
  return (x, y)
end
