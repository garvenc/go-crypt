package crypt

import (
	"errors"
)

var (
	errPaddingIsWrong = errors.New("padding is wrong")
)

type Padding interface {
	// Must ensure the result do not use the array out of boundary of the param slice.
	// This usually means it should return a slice with a new array.
	Pad([]byte) []byte
	// The result may be part of the param slice.
	Unpad([]byte) ([]byte, error)
}

// PKCS#7 padding: See 10.3 of http://tools.ietf.org/html/rfc2315
type Pkcs7Padding struct {
	blockSize int
}

// blockSize: It is the size of bytes in a block.
func NewPkcs7Padding(blockSize int) Pkcs7Padding {
	return Pkcs7Padding{
		blockSize: blockSize,
	}
}

func (p Pkcs7Padding) Pad(buf []byte) []byte {
	paddingSize := p.blockSize - len(buf)%p.blockSize
	result := make([]byte, len(buf)+paddingSize)
	copy(result, buf)
	for i := 0; i < paddingSize; i++ {
		result[len(buf)+i] = byte(paddingSize)
	}
	return result
}

func (p Pkcs7Padding) Unpad(buf []byte) ([]byte, error) {
	paddingSize, err := p.paddingSizeOfUnpad(buf)
	if err != nil {
		return nil, err
	}
	return buf[:len(buf)-paddingSize], nil
}

func (p Pkcs7Padding) paddingSizeOfUnpad(buf []byte) (int, error) {
	length := len(buf)
	if length <= 0 {
		return 0, errPaddingIsWrong
	}
	value := buf[length-1]
	paddingSize := int(value)
	if paddingSize > length {
		return 0, errPaddingIsWrong
	}
	for i := 2; i <= paddingSize; i++ { // The src[length-1] is already value.
		if buf[length-i] != value {
			return 0, errPaddingIsWrong
		}
	}
	return paddingSize, nil
}

// PKCS#5 padding: See 6.1.1 of http://tools.ietf.org/html/rfc2898
type Pkcs5Padding struct {
	pkcs7 Pkcs7Padding
}

func NewPkcs5Padding() Pkcs5Padding {
	return Pkcs5Padding{
		pkcs7: NewPkcs7Padding(8),
	}
}

func (p Pkcs5Padding) Pad(buf []byte) []byte {
	return p.pkcs7.Pad(buf)
}

func (p Pkcs5Padding) Unpad(buf []byte) ([]byte, error) {
	return p.pkcs7.Unpad(buf)
}
