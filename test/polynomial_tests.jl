@testset "secure_rand, generate_polynomial, and evaluate_polynomial" begin
  p = 17  # Example small prime modulus
  field = ShamirSSS.FiniteField(p)
  rng = ShamirSSS.MersenneTwister(1234)  # a seeded RNG for reproducibility

  @testset "secure_rand" begin
    max_value = BigInt(1000)
    rand_value = ShamirSSS.secure_rand(rng, max_value)

    @test 0 <= rand_value < max_value

    # Test that multiple calls produce different results
    rand_value2 = ShamirSSS.secure_rand(rng, max_value)
    @test rand_value != rand_value2
  end

  @testset "generate_polynomial" begin
    secret = ShamirSSS.FieldElement(5, field)
    t = 3  # Degree of the polynomial is t-1 = 2

    coeffs = ShamirSSS.generate_polynomial(rng, secret, t)

    # the first coefficient is the secret
    @test coeffs[1] == secret

    # the polynomial has the correct number of coefficients
    @test length(coeffs) == t

    # all coefficients are in the same field
    for coeff in coeffs
      @test coeff.field == field
    end
  end

  @testset "evaluate_polynomial" begin
    # Define a polynomial f(x) = 5 + 3x + 2x^2 over the field
    secret = ShamirSSS.FieldElement(5, field)
    coeffs = [
      ShamirSSS.FieldElement(5, field),
      ShamirSSS.FieldElement(3, field),
      ShamirSSS.FieldElement(2, field)
    ]

    # Test evaluation at x = 0 (should return the secret)
    x0 = ShamirSSS.FieldElement(0, field)
    @test ShamirSSS.evaluate_polynomial(coeffs, x0) == secret

    # Test evaluation at x = 1
    x1 = ShamirSSS.FieldElement(1, field)
    expected_x1 = ShamirSSS.var"⊕"(ShamirSSS.var"⊕"(coeffs[1], coeffs[2]), coeffs[3]) #coeffs[1] ⊕ coeffs[2] ⊕ coeffs[3]  # f(1) = 5 + 3 + 2 mod 17
    @test ShamirSSS.evaluate_polynomial(coeffs, x1) == expected_x1

    # Test evaluation at x = 2
    x2 = ShamirSSS.FieldElement(2, field)
    expected_x2 = ShamirSSS.var"⊕"(ShamirSSS.var"⊕"(coeffs[1], ShamirSSS.var"⊗"(coeffs[2], x2)), ShamirSSS.var"⊗"(ShamirSSS.var"⊗"(coeffs[3], x2), x2))
    @test ShamirSSS.evaluate_polynomial(coeffs, x2) == expected_x2


    # Test evaluation at a larger value of x
    x3 = ShamirSSS.FieldElement(3, field)
    expected_x3 = ShamirSSS.var"⊕"(ShamirSSS.var"⊕"(coeffs[1], ShamirSSS.var"⊗"(coeffs[2], x3)), ShamirSSS.var"⊗"(ShamirSSS.var"⊗"(coeffs[3], x3), x3))
    @test ShamirSSS.evaluate_polynomial(coeffs, x3) == expected_x3
  end
end