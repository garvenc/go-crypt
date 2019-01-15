package crypt

import (
	"bytes"
	"testing"
)

func TestRsaPkcs1v15PublicEncryptAndPrivateDecrypt(t *testing.T) {
	bits, e := 1024, 65537
	pri := NewRsaPrivate(bits, e)
	pub := NewRsaPublic(pri.GetNBytes(), e)
	input := bytes.Repeat([]byte{0}, 1000)

	enc, err := pub.PublicEncryptPkcs1v15(input)
	if err != nil {
		t.Error("public encrypt err:", err)
	}
	dec, err := pri.PrivateDecryptPkcs1v15(enc)
	if err != nil {
		t.Error("private decrypt err:", err)
	}
	if !bytes.Equal(input, dec) {
		t.Error("the decrypted is not equal to the input")
	}
}

func BenchmarkNewRsaPrivate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewRsaPrivate(1024, 65537)
	}
}

func BenchmarkNewRsaPublic(b *testing.B) {
	b.StopTimer()
	pri := NewRsaPrivate(1024, 65537)
	n := pri.GetNBytes()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		NewRsaPublic(n, 65537)
	}
}

func BenchmarkRsa1024PublicEncryptPkcs1v15With1000Bytes(b *testing.B) {
	b.StopTimer()
	bits, e := 1024, 65537
	pri := NewRsaPrivate(bits, e)
	pub := NewRsaPublic(pri.GetNBytes(), e)
	input := bytes.Repeat([]byte{0}, 1000)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		pub.PublicEncryptPkcs1v15(input)
	}
}

func BenchmarkRsa1024PrivateDecryptPkcs1v15With1000Bytes(b *testing.B) {
	b.StopTimer()
	bits, e := 1024, 65537
	pri := NewRsaPrivate(bits, e)
	pub := NewRsaPublic(pri.GetNBytes(), e)
	input := bytes.Repeat([]byte{0}, 1000)
	enc, err := pub.PublicEncryptPkcs1v15(input)
	if err != nil {
		b.Error("public encrypt err:", err)
	}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		pri.PrivateDecryptPkcs1v15(enc)
	}
}

func BenchmarkRsa1024GetNBytes(b *testing.B) {
	b.StopTimer()
	bits, e := 1024, 65537
	pri := NewRsaPrivate(bits, e)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		pri.GetNBytes()
	}
}
