module ShamirSSS

export split_secret, reconstruct_secret
export share_to_mnemonic, mnemonic_to_share
export ⊕, ⊖, ⊗, /

using Random
using Primes
using SHA
using Base64

include("ssss.jl")
include("wordlist.jl")
include("mnemonic.jl")
include("tofromascii.jl")
include("interface.jl")

end