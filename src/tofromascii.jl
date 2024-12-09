function string_to_number(s::String)::BigInt
  result = BigInt(0)
  for char in s
    result = result * 1000 + Int(char)
  end
  return result
end

function number_to_string(n::BigInt)::String
  chars = Char[]
  while n > 0
    char_code = n % 1000
    pushfirst!(chars, Char(char_code))
    n ÷= 1000
  end
  return String(chars)
end
