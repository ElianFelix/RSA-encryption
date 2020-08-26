# RSA encryption by Elian Felix 08/2020

import random
import sys

sys.setrecursionlimit(2000)  # Allows for larger bit sizes. tested up to ~2500bit


def powmod_sm(base, exp, p):
    """Modded exponentiation function using the square-multiply algorithm.
    takes a base with exponent exp, and modulus p
    returns base raised to exp mod p as result
    """

    exp_b = bin(exp)[3:]  # Converts exp to it's bit representation and gets rid
                          # of binary notation and most significant bit
    product = base

    for b in exp_b:
        product = (product * product) % p
        if b == '1':
            product = (product * base) % p
    return product

# RECURSIVE
# def eucl_a(n1, n2):
#     """GCD implementation.
#     takes 2 values and returns the greatest common divisor between them.
#     """
#
#     if n2 == 0:
#         return n1
#     else:
#         return eucl_a(n2, n1 % n2)


def eucl_a(n1, n2):
    """GCD implementation.
    takes 2 values and returns the greatest common divisor between them.
    """

    while n2 != 0:
        n2, n1 = n1 % n2, n2
    return n1

#RECURSIVE
# def eucl_aex(n1, n2, s0=1, s1=0, t0=0, t1=1):
#     """GCD implementation using extended euclidean algorithm. helps in finding the inverse of either input mod the other.
#     takes integers n1 and n2 and returns a tuple consisting of their gcd and both their inverses (if they exists).
#     """
#
#     if n2 > n1:
#         raise ValueError('Invalid input: first parameter needs to be a bigger value than the second.')
#     if n2 == 0:
#         return n1, s0, t0
#     else:
#         n3 = n1 % n2
#         q = (n1 - n3) // n2
#         s2 = s0 - q * s1
#         t2 = t0 - q * t1
#         return eucl_aex(n2, n3, s1, s2, t1, t2)


def eucl_aex(n1, n2, s0=1, s1=0, t0=0, t1=1):
    """GCD implementation using extended euclidean algorithm. helps in finding the inverse of either input mod the other.
    takes integers n1 and n2 and returns a tuple consisting of their gcd and both their inverses (if they exists).
    """

    if n2 > n1:
        raise ValueError('Invalid input: first parameter needs to be a bigger value than the second.')
    while n2 != 0:
        n3 = n1 % n2
        q = (n1 - n3) // n2
        s2 = s0 - q * s1
        t2 = t0 - q * t1

    return n1, s0, t0


def ur_decompose(p, bits):
    """Helper function for primality test, helps decompose p-1 into 2 raised to an exponent u times some odd number.
    takes integer prime candidate p and integer bits representing the bitsize of p
    returns tuple consisting of exponent u and odd integer r
    """

    m = p - 1
    ubits = range(1, bits // 2)
    for u in ubits:
        r, rem = divmod(m, 2 ** u)
        if r % 2 == 1 and rem == 0:
            return u, r
    return 0, 0


def prime_test(p, bits, s):
    """Primality test implementation based on the Miller-Rabin algorithm.
    takes integers p prime candidate, bits bitsize of p and s security parameter for maintaining minimum accuracy
    returns boolean result of the test
    """
    u, r = ur_decompose(p, bits)
    if (u, r) == (0, 0):
        return False
    repeat = list()
    for i in range(s):
        a = random.randrange(2, p - 2)
        while a in repeat:
            a = random.randrange(2, p-2)
        repeat.append(a)

        z = powmod_sm(a, r, p)
        if z != 1 and z != p - 1:
            for j in range(1, u):
                z = z ** 2 % p
                if z == 1:
                    return False
            if z != p - 1:
                return False
    return True


def s_generator(bits):
    """returns security param dependent on bit size of prime to test for
    """

    if bits < 1:
        raise ValueError('Bit size out of range: must be a positive integer.')
    elif bits < 300:
        s = 11
    elif bits < 400:
        s = 9
    elif bits < 500:
        s = 6
    elif bits < 600:
        s = 5
    else:
        s = 3
    return s


def prime_gen(bits, factor=0):
    """Prime number generator with option of adding list of unwanted values
    takes integer bits determining the bitsize of the prime to be generated and optional list of unwanted values to avoid
    returns a likely prime integer
    """

    s = s_generator(bits)
    p = random.randrange(2 ** (bits - 1) + 1, 2 ** bits, 2)
    repeat = [factor]
    while p in repeat:
        p = random.randrange(2 ** (bits - 1) + 1, 2 ** bits, 2)
    repeat.append(p)

    if prime_test(p, bits, s):
        return p
    else:
        while not prime_test(p, bits, s) or p in repeat:
            p = random.randrange(2 ** (bits - 1) + 1, 2 ** bits, 2)
        repeat.append(p)
        return p


def rsa_key_gen(bits, prev_exp=[], p=0, q=0, n=0, phi_n=0):
    """RSA setup function
    takes in integer bits determining the bitsize of the encryption session and optional list for values to avoid
    and integers p, q, n, phi_n for already calculated setup if wanting to reuse with different exponents
    returns public and private key tuples kpub = (e, n) kpr = (d, p, n)
    """

    if (p, q) == (0, 0):
        fact_bits = bits // 2
        p = prime_gen(fact_bits)
        q = prime_gen(fact_bits, p)
        n = p * q
        phi_n = (p - 1) * (q - 1)

    repeat = prev_exp
    e = random.randrange(1, phi_n - 1)

    while eucl_a(phi_n, e) != 1 or e in repeat:
        if e not in repeat:
            repeat.append(e)
        e = random.randrange(1, phi_n - 1)

    repeat.append(e)
    d = eucl_aex(phi_n, e)[2] % phi_n
    repeat.append(d)

    if len(bin(d)[2:]) >= 0.3 * bits:
        return (e, n), (d, p, q)
    elif len(bin(e)[2:]) >= 0.3 * bits:
        return (e, n), (d, p, q)
    else:
        rsa_key_gen(bits, repeat, p, q, n, phi_n)


def rsa_encrypt(plaintxt, e, n):
    """RSA implementation of encryption using the power-multiply algorithm
    Note: plaintext should be < than n for encryption to be reversible
    """

    return powmod_sm(plaintxt, e, n)


def rsa_decrypt(cipher, d, n):
    """RSA implementation of decryption using the power-multiply algorithm
    Note: plaintext should be < than n for encryption to be reversible
    """

    return powmod_sm(cipher, d, n)

