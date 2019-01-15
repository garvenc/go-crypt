package crypt

import (
	"bytes"
	"testing"
)

func TestPkcs7Padding(t *testing.T) {
	buf := []byte{1, 2, 3, 0, 0, 0}
	bufOrigin := []byte{1, 2, 3, 0, 0, 0}
	bufUnpad := bufOrigin[:3]
	bufPad := []byte{1, 2, 3, 2, 2}

	padding := NewPkcs7Padding(5)
	t.Run("Pad", func(t *testing.T) {
		result := padding.Pad(bufUnpad)
		if !bytes.Equal(result, bufPad) {
			t.Error("Pad wrong result:", result)
		}
		if !bytes.Equal(bufOrigin, buf) {
			t.Error("the origin buf has been modified unexpectedly")
		}
	})
	t.Run("Unpad", func(t *testing.T) {
		result, err := padding.Unpad(bufPad)
		if err != nil {
			t.Error("Unpad:", err)
		}
		if !bytes.Equal(result, bufUnpad) {
			t.Error("Unpad wrong result:", result)
		}
	})
}

func BenchmarkPkcs7PaddingPad(b *testing.B) {
	b.StopTimer()
	blockSize := 16 // aes block size
	padding := NewPkcs7Padding(blockSize)
	data := bytes.Repeat([]byte{0}, blockSize*10+1)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		padding.Pad(data)
	}
}

func BenchmarkPkcs7PaddingUnpad(b *testing.B) {
	b.StopTimer()
	blockSize := 16 // aes block size
	padding := NewPkcs7Padding(blockSize)
	data := bytes.Repeat([]byte{0}, blockSize*10+1)
	bufPad := padding.Pad(data)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		padding.Unpad(bufPad)
	}
}
