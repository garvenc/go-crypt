package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

const (
	Aes128KeySize = 128 / 8       // Size is 16 bytes.
	Aes192KeySize = 192 / 8       // Size is 24 bytes.
	Aes256KeySize = 256 / 8       // Size is 32 bytes.
	AesIvSize     = aes.BlockSize // Size is 16 bytes.
)

var (
	errAesSrcSizeMustBeMultipleOfBlockSize = errors.New("data size must be multiple of block size")
	errAesIvLenMustBeBlockSize             = errors.New("iv length must equal to block size")
)

// The key must be either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
// The iv must be 16 bytes.
//
// Can call HasError to see if it has an error.
func NewAesCbcEncrypter(key, iv []byte, padding Padding) AesBlockModeEncrypter {
	block, err := checkKeyIv(key, iv)
	if err != nil {
		return newAesBlockModeEncrypter(nil, nil, err)
	}
	return newAesBlockModeEncrypter(cipher.NewCBCEncrypter(block, iv), padding, nil)
}

// The key must be either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
// The iv must be 16 bytes.
//
// Can call HasError to see if it has an error.
func NewAesCbcDecrypter(key, iv []byte, padding Padding) AesBlockModeDecrypter {
	block, err := checkKeyIv(key, iv)
	if err != nil {
		return newAesBlockModeDecrypter(nil, nil, err)
	}
	return newAesBlockModeDecrypter(cipher.NewCBCDecrypter(block, iv), padding, nil)
}

// The key must be either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
// The iv must be 16 bytes.
//
// Can call HasError to see if it has an error.
func NewAesCfbEncrypter(key, iv []byte) AesStream {
	block, err := checkKeyIv(key, iv)
	if err != nil {
		return newAesStream(nil, err)
	}
	return newAesStream(cipher.NewCFBEncrypter(block, iv), nil)
}

// The key must be either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
// The iv must be 16 bytes.
//
// Can call HasError to see if it has an error.
func NewAesCfbDecrypter(key, iv []byte) AesStream {
	block, err := checkKeyIv(key, iv)
	if err != nil {
		return newAesStream(nil, err)
	}
	return newAesStream(cipher.NewCFBDecrypter(block, iv), nil)
}

// The key must be either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
// The iv must be 16 bytes.
//
// Can call HasError to see if it has an error.
func NewAesOfb(key, iv []byte) AesStream {
	block, err := checkKeyIv(key, iv)
	if err != nil {
		return newAesStream(nil, err)
	}
	return newAesStream(cipher.NewOFB(block, iv), nil)
}

// The key must be either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
// The iv must be 16 bytes.
//
// Can call HasError to see if it has an error.
func NewAesCtr(key, iv []byte) AesStream {
	block, err := checkKeyIv(key, iv)
	if err != nil {
		return newAesStream(nil, err)
	}
	return newAesStream(cipher.NewCTR(block, iv), nil)
}

func checkKeyIv(key, iv []byte) (cipher.Block, error) {
	if len(iv) != aes.BlockSize {
		return nil, errAesIvLenMustBeBlockSize
	}
	return aes.NewCipher(key)
}

// It may has an error, call HasError to see it.
type AesBlockModeEncrypter struct {
	blockMode cipher.BlockMode
	padding   Padding
	err       error
}

func newAesBlockModeEncrypter(blockMode cipher.BlockMode, padding Padding, err error) AesBlockModeEncrypter {
	return AesBlockModeEncrypter{
		blockMode: blockMode,
		padding:   padding,
		err:       err,
	}
}

func (e AesBlockModeEncrypter) HasError() (error, bool) {
	return e.err, e.err != nil
}

// The result will not share the array of src.
func (e AesBlockModeEncrypter) Encrypt(src []byte) ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}
	buf := e.padding.Pad(src)
	e.blockMode.CryptBlocks(buf, buf)
	return buf, nil
}

// It may has an error, call HasError to see it.
type AesBlockModeDecrypter struct {
	blockMode cipher.BlockMode
	padding   Padding
	err       error
}

func newAesBlockModeDecrypter(blockMode cipher.BlockMode, padding Padding, err error) AesBlockModeDecrypter {
	return AesBlockModeDecrypter{
		blockMode: blockMode,
		padding:   padding,
		err:       err,
	}
}

func (d AesBlockModeDecrypter) HasError() (error, bool) {
	return d.err, d.err != nil
}

// The result will not share the array of src.
func (d AesBlockModeDecrypter) Decrypt(src []byte) ([]byte, error) {
	if d.err != nil {
		return nil, d.err
	}
	if len(src)%d.blockMode.BlockSize() != 0 {
		return nil, errAesSrcSizeMustBeMultipleOfBlockSize
	}
	dst := make([]byte, len(src))
	d.blockMode.CryptBlocks(dst, src)
	return d.padding.Unpad(dst)
}

// It may has an error, call HasError to see it.
type AesStream struct {
	stream cipher.Stream
	err    error
}

func newAesStream(stream cipher.Stream, err error) AesStream {
	return AesStream{
		stream: stream,
		err:    err,
	}
}

func (s AesStream) HasError() (error, bool) {
	return s.err, s.err != nil
}

// The result will not share the array of src.
func (s AesStream) Crypt(src []byte) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	dst := make([]byte, len(src))
	s.stream.XORKeyStream(dst, src)
	return dst, nil
}
