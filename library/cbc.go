package library

import (
	"crypto/cipher"
)

/*
   |--------------------------------------------------------------------------
   | CBC Encrypt
   |--------------------------------------------------------------------------
*/
func CBCEncrypt(block cipher.Block, src, iv []byte, padding string) ([]byte, error) {
	blockSize := block.BlockSize()
	src = Padding(padding, src, blockSize)

	encryptData := make([]byte, len(src))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encryptData, src)

	return encryptData, nil
}

/*
   |--------------------------------------------------------------------------
   | CBC Decrypt
   |--------------------------------------------------------------------------
*/
func CBCDecrypt(block cipher.Block, src, iv []byte, padding string) ([]byte, error) {

	dst := make([]byte, len(src))

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(dst, src)

	dst = UnPadding(padding, dst)

	return dst, nil
}
