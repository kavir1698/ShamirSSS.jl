const BIP39_WORD_INDEX = Dict(word => i - 1 for (i, word) in enumerate(BIP39_WORDLIST))

const MNEMONIC_CHECKSUM_BYTES = 4
const MNEMONIC_LENGTH_BYTES = 2

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

function share_to_bytes(share::Tuple{FieldElement,FieldElement})::Vector{UInt8}
  x, y = share
  components = (number_to_bytes(x.value), number_to_bytes(y.value), number_to_bytes(x.field.p))
  for component in components
    length(component) <= typemax(UInt16) ||
      throw(ArgumentError("Share component too large for mnemonic encoding"))
  end

  buf = UInt8[]
  for component in components
    push!(buf, UInt8(length(component) >> 8), UInt8(length(component) & 0xff))
    append!(buf, component)
  end
  return buf
end

function bytes_to_share(data::AbstractVector{UInt8})
  length(data) >= 2 * 3 || throw(ArgumentError("Malformed share payload"))
  pos = 1

  xlen = (Int(data[pos]) << 8) | Int(data[pos+1]); pos += 2
  pos + xlen - 1 <= length(data) || throw(ArgumentError("Malformed share payload"))
  xb = data[pos:pos+xlen-1]; pos += xlen

  pos + 1 <= length(data) || throw(ArgumentError("Malformed share payload"))
  ylen = (Int(data[pos]) << 8) | Int(data[pos+1]); pos += 2
  pos + ylen - 1 <= length(data) || throw(ArgumentError("Malformed share payload"))
  yb = data[pos:pos+ylen-1]; pos += ylen

  pos + 1 <= length(data) || throw(ArgumentError("Malformed share payload"))
  plen = (Int(data[pos]) << 8) | Int(data[pos+1]); pos += 2
  pos + plen - 1 <= length(data) || throw(ArgumentError("Malformed share payload"))
  pb = data[pos:pos+plen-1]; pos += plen

  pos - 1 == length(data) || throw(ArgumentError("Trailing bytes in share payload"))

  p = bytes_to_number(pb)
  p > 1 || throw(ArgumentError("Invalid modulus in share payload"))
  field = FiniteField(p)
  return (
    FieldElement(bytes_to_number(xb), field),
    FieldElement(bytes_to_number(yb), field),
  )
end

function bytes_to_mnemonic_words(buf::AbstractVector{UInt8})::Vector{String}
  length(buf) <= typemax(UInt16) ||
    throw(ArgumentError("Payload too large for mnemonic encoding"))

  checksum = sha256(buf)[1:MNEMONIC_CHECKSUM_BYTES]
  framed = UInt8[]
  push!(framed, UInt8(length(buf) >> 8), UInt8(length(buf) & 0xff))
  append!(framed, buf)
  append!(framed, checksum)

  bits = BitVector()
  sizehint!(bits, length(framed) * 8)
  for byte in framed, i in 7:-1:0
    push!(bits, (byte >> i) & 0x01 == 0x01)
  end

  words = String[]
  n = length(bits)
  for start in 1:11:n
    index = 0
    for offset in 0:10
      index <<= 1
      position = start + offset
      if position <= n && bits[position]
        index |= 1
      end
    end
    push!(words, BIP39_WORDLIST[index+1])
  end
  return words
end

function mnemonic_words_to_bytes(words::AbstractVector{<:AbstractString})::Vector{UInt8}
  bits = BitVector()
  sizehint!(bits, length(words) * 11)
  for word in words
    index = get(BIP39_WORD_INDEX, lowercase(String(word)), -1)
    index >= 0 || throw(ArgumentError("Unknown word in mnemonic: \"$word\""))
    for i in 10:-1:0
      push!(bits, (index >> i) & 1 == 1)
    end
  end

  n = length(bits)
  n >= MNEMONIC_LENGTH_BYTES * 8 || throw(ArgumentError("Mnemonic is too short"))

  datalen = 0
  for i in 1:MNEMONIC_LENGTH_BYTES*8
    datalen = (datalen << 1) | (bits[i] ? 1 : 0)
  end

  total = MNEMONIC_LENGTH_BYTES + datalen + MNEMONIC_CHECKSUM_BYTES
  expected_words = cld(total * 8, 11)
  n == expected_words * 11 ||
    throw(ArgumentError("Mnemonic has an unexpected number of words"))
  for i in total*8+1:n
    bits[i] && throw(ArgumentError("Mnemonic has non-zero padding bits"))
  end

  buf = Vector{UInt8}(undef, total)
  for i in 1:total
    byte = 0x00
    for j in 0:7
      byte = (byte << 1) | (bits[(i-1)*8+j+1] ? 0x01 : 0x00)
    end
    buf[i] = byte
  end

  data = buf[MNEMONIC_LENGTH_BYTES+1:MNEMONIC_LENGTH_BYTES+datalen]
  stored = buf[MNEMONIC_LENGTH_BYTES+datalen+1:total]
  expected = sha256(data)[1:MNEMONIC_CHECKSUM_BYTES]
  stored == expected ||
    throw(ArgumentError("Mnemonic checksum mismatch (possible transcription error)"))

  return data
end

"""
    share_to_mnemonic(share)::String

Encode a `(x, y)` share as a BIP-39-style mnemonic phrase. The 11-bit word
encoding uses the standard BIP-39 English wordlist and appends a SHA-256
checksum so transcription errors are detected on decoding.
"""
function share_to_mnemonic(share::Tuple{FieldElement,FieldElement})::String
  return join(bytes_to_mnemonic_words(share_to_bytes(share)), " ")
end

"""
    mnemonic_to_share(mnemonic::AbstractString)

Decode a mnemonic phrase produced by [`share_to_mnemonic`](@ref) back into a
`(x, y)` share. Throws if any word is unknown or the checksum does not match.
"""
function mnemonic_to_share(mnemonic::AbstractString)
  words = split(strip(mnemonic))
  isempty(words) && throw(ArgumentError("Empty mnemonic"))
  return bytes_to_share(mnemonic_words_to_bytes(words))
end
