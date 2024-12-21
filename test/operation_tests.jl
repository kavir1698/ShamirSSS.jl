
@testset "FiniteField and FieldElement Operations" begin
  function field_element(value, p)
    field = ShamirSSS.FiniteField(p)
    return ShamirSSS.FieldElement(mod(value, p), field)
  end

  # Define a finite field with a prime modulus
  p = 7  # Example prime modulus
  field = ShamirSSS.FiniteField(p)
  Base.:(==)(a::ShamirSSS.FiniteField, b::ShamirSSS.FiniteField) = a.p == b.p
  
  @testset "FieldElement creation and reduction" begin
    elem1 = ShamirSSS.FieldElement(10, field)
    elem2 = field_element(10, p)
    @test elem1.value == 10
    @test elem2.value == 3  # 10 mod 7 = 3
    @test elem1.field == field
    @test elem2.field == field
  end
  
  @testset "Addition (⊕)" begin
    a = field_element(3, p)
    b = field_element(5, p)
    result = ShamirSSS.var"⊕"(a, b)
    @test result.value == mod(3 + 5, p)  # (3 + 5) mod 7 = 1
    @test result.field == field
  end
  
  @testset "Subtraction (⊖)" begin
    a = field_element(3, p)
    b = field_element(5, p)
    result = ShamirSSS.var"⊖"(a, b) #a ⊖ b
    @test result.value == mod(3 - 5 + p, p)  # (3 - 5 + 7) mod 7 = 5
    @test result.field == field
  end
  
  @testset "Multiplication (⊗)" begin
    a = field_element(3, p)
    b = field_element(5, p)
    result = ShamirSSS.var"⊗"(a, b) #a ⊗ b
    @test result.value == mod(3 * 5, p)  # (3 * 5) mod 7 = 1
    @test result.field == field
  end
  
  # Test operations with elements in different fields
  @testset "Operations with mismatched fields" begin
    field2 = ShamirSSS.FiniteField(11)  # Different field
    a = field_element(3, p)
    b = field_element(5, 11)
    
    @test_throws AssertionError ShamirSSS.var"⊕"(a, b)  # Addition should fail
    @test_throws AssertionError ShamirSSS.var"⊖"(a, b)  # Subtraction should fail
    @test_throws AssertionError ShamirSSS.var"⊗"(a, b)  # Multiplication should fail
  end
  
  # Test edge cases
  @testset "Edge cases" begin
    zero = field_element(0, p)
    one = field_element(1, p)
    max_elem = field_element(p - 1, p)
    
    # Addition with zero
    @test ShamirSSS.var"⊕"(zero, one).value == 1
    @test ShamirSSS.var"⊕"(one, zero).value == 1
    
    # Subtraction with zero
    @test ShamirSSS.var"⊖"(zero, one).value == mod(0 - 1 + p, p)
    @test ShamirSSS.var"⊖"(one, zero).value == 1
    
    # Multiplication with zero
    @test ShamirSSS.var"⊗"(zero, one).value == 0
    @test ShamirSSS.var"⊗"(one, zero).value == 0
    
    # Multiplication with max element
    @test ShamirSSS.var"⊗"(max_elem, one).value == p - 1
    @test ShamirSSS.var"⊗"(one, max_elem).value == p - 1
  end
end