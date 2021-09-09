package library

import (
	"bytes"
)

const PKCS5_PADDING = "PKCS5"
const PKCS7_PADDING = "PKCS7"
const ZEROS_PADDING = "ZEROS"

/*
   |--------------------------------------------------------------------------
   | Padding
   |--------------------------------------------------------------------------
*/
func Padding(padding string, src []byte, blockSize int) []byte {
	switch padding {
	case PKCS5_PADDING:
		src = PKCS5Padding(src, blockSize)
	case PKCS7_PADDING:
		src = PKCS7Padding(src, blockSize)
	case ZEROS_PADDING:
		src = ZerosPadding(src, blockSize)
	}
	return src
}

/*
   |--------------------------------------------------------------------------
   | Un Padding
   |--------------------------------------------------------------------------
*/
func UnPadding(padding string, src []byte) []byte {
	switch padding {
	case PKCS5_PADDING:
		src = PKCS5Unpadding(src)
	case PKCS7_PADDING:
		src = PKCS7UnPadding(src)
	case ZEROS_PADDING:
		src = ZerosUnPadding(src)
	}
	return src
}

/*
   |--------------------------------------------------------------------------
   | PKCS5 UnPadding/Padding
   |--------------------------------------------------------------------------
*/
func PKCS5Padding(src []byte, blockSize int) []byte {
	return PKCS7Padding(src, blockSize)
}

func PKCS5Unpadding(src []byte) []byte {
	return PKCS7UnPadding(src)
}

/*
   |--------------------------------------------------------------------------
   | PKCS7 UnPadding/Padding
   |--------------------------------------------------------------------------
*/
func PKCS7Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func PKCS7UnPadding(src []byte) []byte {
	length := len(src)
	if length == 0 {
		return src
	}
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

/*
   |--------------------------------------------------------------------------
   | Zeros UnPadding/Padding
   |--------------------------------------------------------------------------
*/
func ZerosPadding(src []byte, blockSize int) []byte {
	paddingCount := blockSize - len(src)%blockSize
	if paddingCount == 0 {
		return src
	} else {
		return append(src, bytes.Repeat([]byte{byte(0)}, paddingCount)...)
	}
}

func ZerosUnPadding(src []byte) []byte {
	for i := len(src) - 1; ; i-- {
		if src[i] != 0 {
			return src[:i+1]
		}
	}
}
