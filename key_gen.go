package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"math/rand"
)

// createSeededRandom creates a deterministic random number generator
// using SHA256 hash of `Sun corp` -- meant to imitate JAVA's SecureRandom
func createSeededRandom() *rand.Rand {
	h := sha256.New()
	h.Write([]byte("Sun corp"))

	seedBytes := h.Sum(nil)

	// Convert first 8 bytes to int64 for seed
	seed := int64(binary.BigEndian.Uint64(seedBytes[:8]))
	return rand.New(rand.NewSource(seed))
}

// generatePrime generates a prime number with specified bit length
// Uses Miller-Rabin primality test with high certainty (50 rounds for 1-1/2^50 certainty)
func generatePrime(bitLength int, rng *rand.Rand) (*big.Int, error) {
	for {
		randNum := new(big.Int)

		bytes := make([]byte, (bitLength)/8)
		rng.Read(bytes)

		// Set the randNum from bytes
		randNum.SetBytes(bytes)

		// Ensure it has the correct bit length and high chances of it being prime
		randNum.SetBit(randNum, bitLength-1, 1) // Set MSB to ensure correct bit length (512 in our case)
		randNum.SetBit(randNum, 0, 1)           // Set LSB (make it odd)

		// Test primality with 50 rounds (gives certainty of 1-1/2^50)
		if randNum.ProbablyPrime(50) {
			return randNum, nil
		}
	}
}

// modInverse calculates the modular inverse of a modulo m using the Extended Euclidean Algorithm
// Thank God for this function within big.Int package, we do not need to implement it ourselves
func modInverse(a, m *big.Int) *big.Int {
	return new(big.Int).ModInverse(a, m)
}

func createRSAKey(p, q *big.Int) (*rsa.PrivateKey, error) {
	// Calculate n = p * q
	n := new(big.Int).Mul(p, q)

	// Calculate eulers totient φ(n)= (p-1) * (q-1)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
	phi := new(big.Int).Mul(pMinus1, qMinus1)

	// Choose public exponent e
	e := big.NewInt(257)

	// Verify that gcd(e, φ(n)) = 1
	gcd := new(big.Int).GCD(nil, nil, e, phi)
	if gcd.Cmp(big.NewInt(1)) != 0 {
		return nil, fmt.Errorf("e and φ(n) are not coprime")
	}

	// Calculate private exponent d = e^(-1) mod φ(n)
	d := modInverse(e, phi)
	if d == nil {
		return nil, fmt.Errorf("failed to calculate private exponent")
	}

	// Create RSA private key structure
	privateKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		},
		D:      d,
		Primes: []*big.Int{p, q},
	}

	// precompute private key values for faster calculation operations when using the key
	privateKey.Precompute()

	return privateKey, nil
}

// privateKeyToPEM converts the RSA private key to PEM
func privateKeyToPEM(key *rsa.PrivateKey) []byte {
	// Marshal private key to DER format
	privateKeyDER := x509.MarshalPKCS1PrivateKey(key)

	// Create PEM block
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyDER,
	}

	return pem.EncodeToMemory(privateKeyPEM)
}

// publicKeyToPEM converts the RSA public key to PEM
func publicKeyToPEM(key *rsa.PublicKey) ([]byte, error) {
	publicKeyDER, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %v", err)
	}

	// Create PEM block
	publicKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}

	return pem.EncodeToMemory(publicKeyPEM), nil
}

// GenerateKeys generates RSA key pairs based on two prime numbers (p and q)
func GenerateKeys() (keys map[string]string, err error) {
	rng := createSeededRandom()

	p, err := generatePrime(512, rng)
	if err != nil {
		return nil, fmt.Errorf("failed to generate prime p: %v", err)
	}

	q, err := generatePrime(512, rng)
	if err != nil {
		return nil, fmt.Errorf("failed to generate prime q: %v", err)
	}

	// Verify p ≠ q
	if p.Cmp(q) == 0 {
		return nil, fmt.Errorf("p and q are the same")
	}

	rsaKey, err := createRSAKey(p, q)
	if err != nil {
		fmt.Printf("Error creating RSA key: %v\n", err)
		return nil, err
	}

	privateKeyPEM := privateKeyToPEM(rsaKey)

	publicKeyPEM, err := publicKeyToPEM(&rsaKey.PublicKey)
	if err != nil {
		fmt.Printf("Error exporting public key: %v\n", err)
		return nil, err
	}

	keys = map[string]string{
		"private": string(privateKeyPEM),
		"public":  string(publicKeyPEM),
	}

	return keys, nil
}
