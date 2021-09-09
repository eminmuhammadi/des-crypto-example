package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"

	library "github.com/eminmuhammadi/des-crypto-example/library"
)

func DesECBTest(input []byte, key []byte) error {
	cipher, error := library.DesECBEncrypt(input, key, library.PKCS7_PADDING)
	if error != nil {
		return error
	}

	plaintext, error := library.DesECBDecrypt(cipher, key, library.PKCS7_PADDING)
	if error != nil {
		return error
	}

	test := bytes.Compare(input, plaintext)
	if test != 0 {
		return errors.New("des ecb mode testing failed")
	}

	log.Println(fmt.Sprintf("Des ECB Mode input=%v plaintext=%v cipher=%v\n", input, plaintext, cipher))
	return nil
}

func DesCBCTest(input []byte, key []byte, iv []byte) error {
	cipher, error := library.DesCBCEncrypt(input, key, iv, library.PKCS7_PADDING)
	if error != nil {
		return error
	}

	plaintext, error := library.DesCBCDecrypt(cipher, key, iv, library.PKCS7_PADDING)
	if error != nil {
		return error
	}

	test := bytes.Compare(input, plaintext)
	if test != 0 {
		return errors.New("des cbc mode testing failed")
	}

	log.Println(fmt.Sprintf("Des CBC Mode input=%v plaintext=%v cipher=%v\n", input, plaintext, cipher))
	return nil
}

func main() {
	key := []byte("12345678")
	iv := []byte("12345678")
	input := []byte("12345678")

	error := DesECBTest(input, key)
	if error != nil {
		panic(error)
	}

	error = DesCBCTest(input, key, iv)
	if error != nil {
		panic(error)
	}
}
