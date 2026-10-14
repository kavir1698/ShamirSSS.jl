const BIP39_WORD_INDEX = Dict(word => i - 1 for (i, word) in enumerate(BIP39_WORDLIST))

const MNEMONIC_CHECKSUM_BYTES = 4
const MNEMONIC_LENGTH_BYTES = 2

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
    share_to_mnemonic(share; t, set_id=(0x00, 0x00, 0x00, 0x00))::String

Encode a `(x, y)` share as a BIP-39-style mnemonic phrase. The 11-bit word
encoding uses the standard BIP-39 English wordlist and appends a SHA-256
checksum so transcription errors are detected on decoding.

`t` (the threshold) is required and `set_id` is copied into the share header so
that [`reconstruct_secret`](@ref) can reject mismatched or insufficient share
sets.
"""
function share_to_mnemonic(
  share::Tuple{FieldElement,FieldElement};
  t::Integer,
  set_id::NTuple{4,UInt8}=SHARE_DEFAULT_SET_ID,
)::String
  return join(bytes_to_mnemonic_words(share_to_bytes(share; t=t, set_id=set_id)), " ")
end

"""
    mnemonic_to_share(mnemonic::AbstractString)

Decode a mnemonic phrase produced by [`share_to_mnemonic`](@ref) back into a
[`Share`](@ref). Throws if any word is unknown or the checksum does not match.
"""
function mnemonic_to_share(mnemonic::AbstractString)
  words = split(strip(mnemonic))
  isempty(words) && throw(ArgumentError("Empty mnemonic"))
  return bytes_to_share(mnemonic_words_to_bytes(words))
end
