package crypt

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestAesCbc(t *testing.T) {
	key := []byte("11112222333344445555666677778888")
	iv := []byte("1234567812345678")
	data := "I love this girl! Does she?"
	result := "DC9HZuq4EOq7fO+vP2Qs2Oh9zfaA8TI/u6tHN38yvcM="

	t.Run("encrypt", func(t *testing.T) {
		encrypter := NewAesCbcEncrypter(key, iv, NewPkcs7Padding(AesBlockSize))
		enc, err := encrypter.Encrypt([]byte(data))
		if err != nil {
			t.Error("encrypt:", err)
		}
		str := base64.StdEncoding.EncodeToString(enc)
		if str != result {
			t.Error("encrypt result is wrong:", str)
		}
	})
	t.Run("decrypt", func(t *testing.T) {
		buf, _ := base64.StdEncoding.DecodeString(result)
		decrypter := NewAesCbcDecrypter(key, iv, NewPkcs7Padding(AesBlockSize))
		dec, err := decrypter.Decrypt(buf)
		if err != nil {
			t.Error("decrypt:", err)
		}
		if string(dec) != data {
			t.Error("decrypt result is wrong:", dec)
		}
	})
}

func TestAesCfb(t *testing.T) {
	key := []byte("11112222333344445555666677778888")
	iv := []byte("1234567812345678")
	data := "I love this girl! Does she?"
	result := "+HVXA7n2iUln6vXL2buTcUuN844bbH5c1XEz"

	t.Run("encrypt", func(t *testing.T) {
		encrypter := NewAesCfbEncrypter(key, iv)
		enc, err := encrypter.Crypt([]byte(data))
		if err != nil {
			t.Error("encrypt:", err)
		}
		str := base64.StdEncoding.EncodeToString(enc)
		if str != result {
			t.Error("encrypt result is wrong:", str)
		}
	})
	t.Run("decrypt", func(t *testing.T) {
		buf, _ := base64.StdEncoding.DecodeString(result)
		decrypter := NewAesCfbDecrypter(key, iv)
		dec, err := decrypter.Crypt(buf)
		if err != nil {
			t.Error("decrypt:", err)
		}
		if string(dec) != data {
			t.Error("decrypt result is wrong:", dec)
		}
	})
}

func TestAesOfb(t *testing.T) {
	key := []byte("11112222333344445555666677778888")
	iv := []byte("1234567812345678")
	data := "I love this girl! Does she?"
	result := "+HVXA7n2iUln6vXL2buTcQ/iMrzkSWcxWYEn"

	t.Run("encrypt", func(t *testing.T) {
		encrypter := NewAesOfb(key, iv)
		enc, err := encrypter.Crypt([]byte(data))
		if err != nil {
			t.Error("encrypt:", err)
		}
		str := base64.StdEncoding.EncodeToString(enc)
		if str != result {
			t.Error("encrypt result is wrong:", str)
		}
	})
	t.Run("decrypt", func(t *testing.T) {
		buf, _ := base64.StdEncoding.DecodeString(result)
		decrypter := NewAesOfb(key, iv)
		dec, err := decrypter.Crypt(buf)
		if err != nil {
			t.Error("decrypt:", err)
		}
		if string(dec) != data {
			t.Error("decrypt result is wrong:", dec)
		}
	})
}

func TestAesCtr(t *testing.T) {
	key := []byte("11112222333344445555666677778888")
	iv := []byte("1234567812345678")
	data := "I love this girl! Does she?"
	result := "+HVXA7n2iUln6vXL2buTcfv28+am206YJuzC"

	t.Run("encrypt", func(t *testing.T) {
		encrypter := NewAesCtr(key, iv)
		enc, err := encrypter.Crypt([]byte(data))
		if err != nil {
			t.Error("encrypt:", err)
		}
		str := base64.StdEncoding.EncodeToString(enc)
		if str != result {
			t.Error("encrypt result is wrong:", str)
		}
	})
	t.Run("decrypt", func(t *testing.T) {
		buf, _ := base64.StdEncoding.DecodeString(result)
		decrypter := NewAesCtr(key, iv)
		dec, err := decrypter.Crypt(buf)
		if err != nil {
			t.Error("decrypt:", err)
		}
		if string(dec) != data {
			t.Error("decrypt result is wrong:", dec)
		}
	})
}

func BenchmarkAes256CbcEncrypt1000Bytes(b *testing.B) {
	b.StopTimer()
	key := bytes.Repeat([]byte("a"), Aes256KeySize)
	iv := bytes.Repeat([]byte("b"), AesIvSize)
	data := bytes.Repeat([]byte("s"), 1000)
	encrypter := NewAesCbcEncrypter(key, iv, NewPkcs7Padding(8))
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		encrypter.Encrypt(data)
	}
}

func BenchmarkAes256CbcDecrypt1000Bytes(b *testing.B) {
	b.StopTimer()
	key := bytes.Repeat([]byte("a"), Aes256KeySize)
	iv := bytes.Repeat([]byte("b"), AesIvSize)
	data := bytes.Repeat([]byte("s"), 1000)
	encrypter := NewAesCbcEncrypter(key, iv, NewPkcs7Padding(AesBlockSize))
	decrypter := NewAesCbcDecrypter(key, iv, NewPkcs7Padding(AesBlockSize))
	enc, err := encrypter.Encrypt(data)
	if err != nil {
		b.Error("prepare enc data fail:", err)
		return
	}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		decrypter.Decrypt(enc)
	}
}

func BenchmarkAes256CfbEncrypt1000Bytes(b *testing.B) {
	b.StopTimer()
	key := bytes.Repeat([]byte("a"), Aes256KeySize)
	iv := bytes.Repeat([]byte("b"), AesIvSize)
	data := bytes.Repeat([]byte("s"), 1000)
	encrypter := NewAesCfbEncrypter(key, iv)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		encrypter.Crypt(data)
	}
}

func BenchmarkAes256CfbDecrypt1000Bytes(b *testing.B) {
	b.StopTimer()
	key := bytes.Repeat([]byte("a"), Aes256KeySize)
	iv := bytes.Repeat([]byte("b"), AesIvSize)
	data := bytes.Repeat([]byte("s"), 1000)
	encrypter := NewAesCfbEncrypter(key, iv)
	decrypter := NewAesCfbDecrypter(key, iv)
	enc, err := encrypter.Crypt(data)
	if err != nil {
		b.Error("prepare enc data fail:", err)
		return
	}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		decrypter.Crypt(enc)
	}
}

func BenchmarkAes256OfbCrypt1000Bytes(b *testing.B) {
	b.StopTimer()
	key := bytes.Repeat([]byte("a"), Aes256KeySize)
	iv := bytes.Repeat([]byte("b"), AesIvSize)
	data := bytes.Repeat([]byte("s"), 1000)
	crypter := NewAesOfb(key, iv)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		crypter.Crypt(data)
	}
}

func BenchmarkAes256CtrCrypt1000Bytes(b *testing.B) {
	b.StopTimer()
	key := bytes.Repeat([]byte("a"), Aes256KeySize)
	iv := bytes.Repeat([]byte("b"), AesIvSize)
	data := bytes.Repeat([]byte("s"), 1000)
	crypter := NewAesCtr(key, iv)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		crypter.Crypt(data)
	}
}
