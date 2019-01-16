# Example

## AES

The example of AES-256-CBC, others are similar.

```go
package main

import (
	"bytes"
	"fmt"

	"github.com/garvenc/go-crypt" // Package name is crypt.
)

func main() {
	input := "123456"
	key := bytes.Repeat([]byte{'a'}, crypt.Aes256KeySize)
	iv := bytes.Repeat([]byte{'b'}, crypt.AesIvSize)

	encrypter := crypt.NewAesCbcEncrypter(key, iv, crypt.NewPkcs7Padding(crypt.AesBlockSize))
	decrypter := crypt.NewAesCbcDecrypter(key, iv, crypt.NewPkcs7Padding(crypt.AesBlockSize))
	enc, err := encrypter.Encrypt([]byte(input))
	if err != nil {
		fmt.Println("encrypt:", err)
		return
	}
	fmt.Println("encrypt result:", enc)
	dec, err := decrypter.Decrypt(enc)
	if err != nil {
		fmt.Println("decrypt:", err)
		return
	}
	fmt.Println("decrypt result:", dec)
	fmt.Println("decrypt result string:", string(dec))
}
```

Output:

```
encrypt result: [91 14 236 68 51 250 203 219 122 12 215 110 44 233 203 201]
decrypt result: [49 50 51 52 53 54]
decrypt result string: 123456
```

## RSA

```go
package main

import (
	"fmt"

	"github.com/garvenc/go-crypt" // Package name is crypt.
)

func main() {
	input := "123456"
	bits := 1024
	e := 65537

	pri := crypt.NewRsaPrivate(bits, e)
	n := pri.GetNBytes()
	fmt.Println("n:", n) // Each execution result is different.
	pub := crypt.NewRsaPublic(n, e)
	enc, err := pub.PublicEncryptPkcs1v15([]byte(input))
	if err != nil {
		fmt.Println("public encrypt:", err)
		return
	}
	fmt.Println("public encrypt result:", enc) // Each execution result is different.
	dec, err := pri.PrivateDecryptPkcs1v15(enc)
	if err != nil {
		fmt.Println("privage decrypt:", err)
		return
	}
	fmt.Println("private decrypt result:", dec)
	fmt.Println("private decrypt result string:", string(dec))
}
```

Output:

```
n: [231 233 187 169 26 184 91 211 208 182 160 66 238 180 224 9 15 99 152 165 75 175 226 248 192 140 196 197 75 239 37 136 125 1 175 49 191 180 166 37 152 3 29 245 203 235 38 130 89 155 145 22 75 94 159 180 174 190 160 196 32 29 199 101 79 167 191 75 252 222 141 187 1 158 41 91 208 94 249 131 61 87 241 35 224 199 251 102 51 248 245 55 222 243 202 251 2 235 55 75 98 181 229 22 98 26 20 14 182 44 158 36 142 66 208 214 177 43 15 105 97 103 253 20 140 76 209 91]
public encrypt result: [96 84 95 118 182 215 53 138 124 22 113 38 222 128 203 59 21 199 127 91 211 250 216 153 146 248 82 87 15 36 73 144 157 228 63 143 182 141 132 148 106 97 18 160 42 34 185 4 243 247 234 237 135 73 155 228 188 143 83 195 177 2 24 141 158 246 115 30 150 76 65 151 5 164 158 64 89 12 242 43 155 65 26 192 86 26 147 85 16 255 1 50 53 189 38 120 8 182 26 50 35 236 205 56 188 208 68 33 177 106 110 23 114 86 151 223 200 108 40 58 2 142 85 61 246 169 78 37]
private decrypt result: [49 50 51 52 53 54]
private decrypt result string: 123456
```
