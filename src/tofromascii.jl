# A fixed, non-zero header makes the byte <-> integer encoding injective: it
# preserves leading zero bytes and an empty string encodes to a non-zero value.
# Four bytes also give a strong (≈2^-32) rejection of invalid decoded values.
const SECRET_SENTINEL = UInt8[0x53, 0x53, 0x53, 0x01]
const SECRET_SENTINEL_LENGTH = length(SECRET_SENTINEL)

"""
    string_to_number(s::String)::BigInt

Encode `s` as a non-negative integer by interpreting its raw UTF-8 bytes as a
big-endian number and prefixing a fixed sentinel. The sentinel guarantees the
encoding is injective: leading zero bytes are preserved, an empty string encodes
to a non-zero value, and every code point round-trips.

See also [`number_to_string`](@ref).
"""
function string_to_number(s::String)::BigInt
  return bytes_to_number(vcat(SECRET_SENTINEL, Vector{UInt8}(codeunits(s))))
end

"""
    number_to_string(n::BigInt)::String

Inverse of [`string_to_number`](@ref).

Throws an `ArgumentError` if `n` is not a valid encoding. A random or
inconsistent value (for example, the result of interpolating with too few or
mismatched shares) will fail the sentinel check rather than silently decode to a
different string.
"""
function number_to_string(n::BigInt)::String
  n > 0 || throw(ArgumentError("Decoded value is not a valid encoded secret"))
  bytes = number_to_bytes(n)
  length(bytes) >= SECRET_SENTINEL_LENGTH ||
    throw(ArgumentError("Decoded value is not a valid encoded secret"))
  bytes[1:SECRET_SENTINEL_LENGTH] == SECRET_SENTINEL ||
    throw(ArgumentError("Decoded value is not a valid encoded secret (corrupted or insufficient shares)"))
  return String(bytes[SECRET_SENTINEL_LENGTH+1:end])
end

# The base-1000 secret encoding used up to and including version 0.3.0. It is
# retained only to decode shares produced by older releases. The encoding is not
# injective for code points >= 1000 and cannot represent leading zero bytes, so
# legacy reconstruction is best-effort and ASCII-only.
function legacy_string_to_number(s::String)::BigInt
  result = BigInt(0)
  for char in s
    result = result * 1000 + Int(char)
  end
  return result
end

function legacy_number_to_string(n::BigInt)::String
  chars = Char[]
  while n > 0
    char_code = n % 1000
    pushfirst!(chars, Char(char_code))
    n ÷= 1000
  end
  return String(chars)
end
