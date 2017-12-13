package main

import (
  "fmt"
  "crypto/aes"
  "bytes"
  "crypto/cipher"
  "encoding/base64"
)

type CBC256 struct {
  Key []byte
  IV []byte
}

func (c CBC256) EncryptByCBC(plainText []byte) []byte {

    block, err := aes.NewCipher(c.Key)
    if err != nil {
      panic(err)
    }

    paddedPlaintext := c.PadByPkcs7([]byte(plainText))

    cipherText := make([]byte, aes.BlockSize+len(paddedPlaintext))

    mode := cipher.NewCBCEncrypter(block, c.IV)
    mode.CryptBlocks(cipherText[:], paddedPlaintext)

    return cipherText[:len(cipherText)-aes.BlockSize]
}

func (c CBC256) DecryptByCBC(chipherText []byte) []byte {

    decrypted := make([]byte, len(chipherText))

    block, err := aes.NewCipher(c.Key)
    if err != nil {
      panic(err)
    }

    mode := cipher.NewCBCDecrypter(block, c.IV)
    mode.CryptBlocks(decrypted, chipherText[:])

    return decrypted[:len(decrypted)-int(decrypted[len(decrypted)-1])]
}

func (c CBC256) PadByPkcs7(data []byte) []byte {
    padSize := aes.BlockSize
    if len(data) % aes.BlockSize != 0 {
        padSize = aes.BlockSize - (len(data)) % aes.BlockSize
    }

    pad := bytes.Repeat([]byte{byte(padSize)}, padSize)
    return append(data, pad...)
}


func main(){

  plainText := []byte("Dtesq8FUhBW01uRoDCTBqMcdflvrqcQKF9")
  key := []byte("SEA8nZsNGsN6GMfusg8OyegVzbegAgea")//256
  iv := []byte("abcdabcdabcdabcd")//128

  cbc := new(CBC256)
  cbc.Key = key
  cbc.IV = iv

  chipherText := cbc.EncryptByCBC(plainText)

  chipherTextBase64Encoded := base64.StdEncoding.EncodeToString(chipherText)

  fmt.Println("EncryptByCBC base64encoded :",chipherTextBase64Encoded)

  chipherTextBase64Decoded, err := base64.StdEncoding.DecodeString(chipherTextBase64Encoded)
   if err != nil {
     fmt.Println("base64 decoding error:", err)
   }

  decrypted := cbc.DecryptByCBC(chipherTextBase64Decoded)

  fmt.Println("Decrypted plainText:", string(decrypted[:]))
}
