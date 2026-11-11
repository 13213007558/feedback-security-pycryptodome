#
# Counterexamples for Crypto.Protocol.SecretSharing.Shamir (PyCryptodome 4.4.0)
#
# Run:
#   .venv/bin/python shamir_counterexamples.py
#
# Every scenario prints whether combine() raised, and compares the reconstructed
# value against the original secret. The whole point: combine() performs NO
# authentication, so "no exception" never means "this is the original secret".
#
from binascii import hexlify
import os
import sys

# Make sure we use the in-repo library even if the script is launched outside
# the venv.
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "lib"))

from Crypto.Protocol.SecretSharing import Shamir  # noqa: E402
from Crypto.PublicKey import ECC  # noqa: E402
from Crypto.Signature import eddsa  # noqa: E402
from Crypto.Hash import SHA512  # noqa: E402

K, N = 3, 5
SECRET = bytes.fromhex("00112233445566778899aabbccddeeff")


def hx(b: bytes) -> str:
    return hexlify(b).decode()


def attempt(label, shares, ssss=False, expect_secret=SECRET):
    """Run combine, report whether it raised and whether the output is correct."""
    print(f"\n=== {label} ===")
    print("input indices:", [s[0] for s in shares])
    try:
        recovered = Shamir.combine(shares, ssss=ssss)
    except Exception as exc:  # noqa: BLE001 - we want to show any failure mode
        print(f"combine() RAISED  {type(exc).__name__}: {exc}")
        return None
    ok = (recovered == expect_secret)
    print("combine() did NOT raise")
    print(f"  recovered = {hx(recovered)}")
    print(f"  original  = {hx(expect_secret)}")
    print(f"  matches original secret? {ok}")
    return recovered


def main():
    print(f"PyCryptodome Shamir demo  k={K} n={N}")
    print(f"secret = {hx(SECRET)}")

    shares_a = Shamir.split(K, N, SECRET)                 # default polynomial
    shares_b = Shamir.split(K, N, SECRET)                 # independent split, same secret
    shares_s = Shamir.split(K, N, SECRET, ssss=True)      # ssss-style polynomial

    # Sanity: an honest quorum reconstructs the secret.
    attempt("0. honest quorum (baseline, must work)", shares_a[:K])

    # --- Case 1: duplicate index -------------------------------------------
    # combine() tracks indices only; a repeated index is the one thing it
    # deterministically rejects (SecretSharing.py, "Duplicate share").
    dup_same = [shares_a[0], shares_a[0], shares_a[2]]
    attempt("1a. duplicate index, identical share", dup_same)

    dup_diff_value = [shares_a[0], (1, shares_b[0][1]), shares_a[2]]
    attempt("1b. duplicate index, DIFFERENT 16-byte value", dup_diff_value)

    # --- Case 2: mixing two independent splits -----------------------------
    # Same secret, same k/n, same indices -- but distinct random polynomials.
    # Each tuple is individually well-formed; nothing links them to a batch.
    mixed = [shares_a[0], shares_b[1], shares_a[2]]
    attempt("2. mix shares from two different splits of the SAME secret", mixed)

    # --- Case 3: tamper one well-formed share ------------------------------
    # Flip one bit. Length stays 16, index stays valid, so every structural
    # check passes; interpolation silently returns another 16-byte value.
    tampered = list(shares_a[:K])
    bad_y = bytearray(tampered[0][1])
    bad_y[0] ^= 0x01
    tampered[0] = (tampered[0][0], bytes(bad_y))
    attempt("3. one legal-length share flipped by a single bit", tampered)

    # --- Case 4: ssss flag mismatch ----------------------------------------
    # ssss shares encode an extra x^k term. combine(ssss=False) skips the
    # compensating term, so the field points no longer lie on one degree k-1
    # polynomial -> a wrong constant term, with no error.
    attempt("4a. ssss-generated shares combined with ssss=False (mismatch)",
            shares_s[:K], ssss=False)
    attempt("4b. same ssss shares combined correctly with ssss=True",
            shares_s[:K], ssss=True)
    attempt("4c. normal shares combined with ssss=True (reverse mismatch)",
            shares_a[:K], ssss=True)

    # --- Bonus case A: fewer than k shares ---------------------------------
    # combine() cannot know k: it just interpolates whatever points it got.
    # k-1 points define a different (lower-degree) polynomial whose constant
    # term is random-looking. No exception.
    attempt("A. only k-1=2 shares presented (below threshold)", shares_a[:K - 1])

    # --- Bonus case B: why a plain digest cannot stop an input-holder ------
    # Over GF(2^128), reconstruction is linear in the share values. Flipping
    # bit mask d in one share flips a PREDICTABLE mask in the recovered key.
    # An attacker who holds the inputs can therefore choose the target key and
    # re-hash; a bare SHA-256 over shares has no secret and cannot stop this.
    print("\n=== B. linearity: attacker-chosen key change ===")
    delta = bytes.fromhex("deadbeef000000000000000000000000")
    crafted = list(shares_a[:K])
    crafted[0] = (crafted[0][0],
                  bytes(x ^ y for x, y in zip(crafted[0][1], delta)))
    recovered_crafted = Shamir.combine(crafted)
    observed = bytes(x ^ y for x, y in zip(SECRET, recovered_crafted))
    print(f"injected delta in share[0] = {hx(delta)}")
    print(f"observed key delta         = {hx(observed)}")
    print("delta maps 1:1 to the output -> attacker fully controls the 'key'")
    print("and can recompute any plain hash; a digest alone is not a defence.")

    # --- What actually detects tampering: an authenticated manifest --------
    print("\n=== C. Ed25519-signed manifest DOES reject the tampered quorum ===")
    key = ECC.generate(curve="ed25519")
    signer = eddsa.new(key, "rfc8032")

    def manifest(quorum):
        m = b"v=1|batch=B42|k=3|n=5|" + b";".join(
            f"{i}:{hx(y)}".encode() for i, y in quorum
        )
        # RFC 8032 Ed25519 in PyCryptodome requires a pre-hashed SHA-512 object.
        return m, signer.sign(SHA512.new(m))

    verifier = eddsa.new(key.public_key(), "rfc8032")
    # The signer attests the honest quorum once, at issuance time.
    m_good, sig_good = manifest(shares_a[:K])
    # The attacker tampers with a share but does NOT possess the signing key,
    # so they cannot re-sign. Recompute only the message, keep the old signature.
    m_bad, _resigned = manifest(tampered)
    try:
        verifier.verify(SHA512.new(m_good), sig_good)
        print("honest quorum vs original signature: VERIFIED")
    except Exception as exc:  # noqa: BLE001
        print("honest quorum signature FAILED:", exc)
    try:
        verifier.verify(SHA512.new(m_bad), sig_good)
        print("tampered quorum vs original signature: VERIFIED (bad!)")
    except Exception:
        print("tampered quorum vs original signature: REJECTED (no signing key)")


if __name__ == "__main__":
    main()
