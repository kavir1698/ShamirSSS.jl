module ShamirSSS

export split_secret, reconstruct_secret
export ⊕, ⊖, ⊗

using Random
using Primes
using SHA
using Base64

include("ssss.jl")
include("tofromascii.jl")
include("interface.jl")

end