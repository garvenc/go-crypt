package crypt

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"math/big"
)

var errRsaPublicKeySize = errors.New("rsa public key size illegal")

// This is copy from crypto/rsa.
var bigOne = big.NewInt(1)

// It may has an error, call HasError to see it.
type RsaPrivate struct {
	priKey *rsa.PrivateKey
	err    error
}

// bits:
// The bit size of rsa key. It must be multiple of 8.
// The byte size of N equals to bits/8. 1024 usually, 2048 in some important cases.
//
// e:
// The public exponent E value. Usually use 65537.
//
// Can call HasError to see if it has an error.
func NewRsaPrivate(bits, e int) RsaPrivate {
	pri := RsaPrivate{}
	if bits%8 != 0 {
		pri.err = errRsaPublicKeySize
		return pri
	}
	key, err := generateMultiPrimeKey(rand.Reader, 2, bits, e) // Call it like what in crypto/rsa.GenerateKey.
	if err != nil {
		pri.err = err
		return pri
	}
	pri.priKey = key
	pri.err = nil
	return pri
}

func (p RsaPrivate) HasError() (error, bool) {
	return p.err, p.err != nil
}

// Public encrypt of PKCS#1 v1.5.
// Each bits/8-11 or less bytes will be encrypted to bits/8 bytes.
// If len(data) == 0, will return an empty buf too.
//
// The result will not share the array of data.
func (p RsaPrivate) PublicEncryptPkcs1v15(data []byte) ([]byte, error) {
	if p.err != nil {
		return nil, p.err
	}
	return publicEncryptPkcs1v15(&p.priKey.PublicKey, data)
}

// Private Decrypt of PKCS#1 v1.5.
// Each bits/8 bytes will be decrypted to bits/8-11 or less bytes.
// If len(data) == 0, will return an empty buf too.
//
// The result will not share the array of data.
func (p RsaPrivate) PrivateDecryptPkcs1v15(data []byte) ([]byte, error) {
	if p.err != nil {
		return nil, p.err
	}
	return privateDecryptPkcs1v15(p.priKey, data)
}

// If p has error, return nil.
func (p RsaPrivate) GetNBytes() []byte {
	if p.err != nil {
		return nil
	}
	return p.priKey.PublicKey.N.Bytes()
}

type RsaPublic struct {
	pubKey *rsa.PublicKey
}

// n:
// The bytes of N. The size of N is the length of the public modulus.
//
// e:
// The public exponent E value. Usually use 65537.
func NewRsaPublic(n []byte, e int) RsaPublic {
	return RsaPublic{
		pubKey: &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: e,
		},
	}
}

// Public encrypt of PKCS#1 v1.5.
// Each bits/8-11 or less bytes will be encrypted to bits/8 bytes.
// If len(data) == 0, will return an empty buf too.
//
// The result will not share the array of data.
func (pub *RsaPublic) PublicEncryptPkcs1v15(data []byte) ([]byte, error) {
	return publicEncryptPkcs1v15(pub.pubKey, data)
}

func publicEncryptPkcs1v15(pub *rsa.PublicKey, data []byte) ([]byte, error) {
	// Each input must be not longer than the length of bytes of the public modulus minus 11 bytes.
	// The output is always equal to the length of bytes of the public modulus.
	eachSize := pub.N.BitLen()/8 - 11
	if eachSize <= 0 {
		return nil, errRsaPublicKeySize
	}
	var outputs [][]byte
	for encSize, leftSize, thisSize := 0, len(data), 0; leftSize > 0; {
		if leftSize > eachSize {
			thisSize = eachSize
		} else {
			thisSize = leftSize
		}
		out, err := rsa.EncryptPKCS1v15(rand.Reader, pub, data[encSize:(encSize+thisSize)])
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, out)
		encSize += thisSize
		leftSize -= thisSize
	}
	return bytes.Join(outputs, nil), nil
}

func privateDecryptPkcs1v15(pri *rsa.PrivateKey, data []byte) ([]byte, error) {
	// See publicEncryptPkcs1v15. The logical procedure is reversed.
	eachSize := pri.PublicKey.N.BitLen() / 8
	if eachSize <= 0 {
		return nil, errRsaPublicKeySize
	}
	var outputs [][]byte
	for encSize, leftSize, thisSize := 0, len(data), 0; leftSize > 0; {
		if leftSize > eachSize {
			thisSize = eachSize
		} else {
			thisSize = leftSize
		}
		out, err := rsa.DecryptPKCS1v15(rand.Reader, pri, data[encSize:(encSize+thisSize)])
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, out)
		encSize += thisSize
		leftSize -= thisSize
	}
	return bytes.Join(outputs, nil), nil
}

// This is copy from crypto/rsa.GenerateMultiPrimeKey, except pass an additional e param and can set priv.E as it.
// In the rsa.GenerateMultiPrimeKey, priv.E is always 65537.
func generateMultiPrimeKey(random io.Reader, nprimes int, bits int, e int) (priv *rsa.PrivateKey, err error) {
	priv = new(rsa.PrivateKey)
	priv.E = e // In crypto/rsa.GenerateMultiPrimeKey, it is always 65537.

	if nprimes < 2 {
		return nil, errors.New("crypto/rsa: GenerateMultiPrimeKey: nprimes must be >= 2")
	}

	primes := make([]*big.Int, nprimes)

NextSetOfPrimes:
	for {
		todo := bits
		// crypto/rand should set the top two bits in each prime.
		// Thus each prime has the form
		//   p_i = 2^bitlen(p_i) × 0.11... (in base 2).
		// And the product is:
		//   P = 2^todo × α
		// where α is the product of nprimes numbers of the form 0.11...
		//
		// If α < 1/2 (which can happen for nprimes > 2), we need to
		// shift todo to compensate for lost bits: the mean value of 0.11...
		// is 7/8, so todo + shift - nprimes * log2(7/8) ~= bits - 1/2
		// will give good results.
		if nprimes >= 7 {
			todo += (nprimes - 2) / 5
		}
		for i := 0; i < nprimes; i++ {
			primes[i], err = rand.Prime(random, todo/(nprimes-i))
			if err != nil {
				return nil, err
			}
			todo -= primes[i].BitLen()
		}

		// Make sure that primes is pairwise unequal.
		for i, prime := range primes {
			for j := 0; j < i; j++ {
				if prime.Cmp(primes[j]) == 0 {
					continue NextSetOfPrimes
				}
			}
		}

		n := new(big.Int).Set(bigOne)
		totient := new(big.Int).Set(bigOne)
		pminus1 := new(big.Int)
		for _, prime := range primes {
			n.Mul(n, prime)
			pminus1.Sub(prime, bigOne)
			totient.Mul(totient, pminus1)
		}
		if n.BitLen() != bits {
			// This should never happen for nprimes == 2 because
			// crypto/rand should set the top two bits in each prime.
			// For nprimes > 2 we hope it does not happen often.
			continue NextSetOfPrimes
		}

		g := new(big.Int)
		priv.D = new(big.Int)
		y := new(big.Int)
		e := big.NewInt(int64(priv.E))
		g.GCD(priv.D, y, e, totient)

		if g.Cmp(bigOne) == 0 {
			if priv.D.Sign() < 0 {
				priv.D.Add(priv.D, totient)
			}
			priv.Primes = primes
			priv.N = n

			break
		}
	}

	priv.Precompute()
	return
}
