package library

import (
	"crypto/des"
)

/*
   |--------------------------------------------------------------------------
   | Des ECB Encryption
   |--------------------------------------------------------------------------
*/
func DesECBEncrypt(src, key []byte, padding string) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return ECBEncrypt(block, src, padding)
}

/*
   |--------------------------------------------------------------------------
   | Des ECB Decryption
   |--------------------------------------------------------------------------
*/
func DesECBDecrypt(src, key []byte, padding string) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return ECBDecrypt(block, src, padding)
}

/*
   |--------------------------------------------------------------------------
   | Des CBC Encryption
   |--------------------------------------------------------------------------
*/
func DesCBCEncrypt(src, key, iv []byte, padding string) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return CBCEncrypt(block, src, iv, padding)
}

/*
   |--------------------------------------------------------------------------
   | Des CBC Decryption
   |--------------------------------------------------------------------------
*/
func DesCBCDecrypt(src, key, iv []byte, padding string) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return CBCDecrypt(block, src, iv, padding)
}
