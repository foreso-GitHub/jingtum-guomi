package main

import (
	"../guomi"
	"bytes"
	"errors"
	"fmt"
	"log"
	"testing"
)

//region hash

func TestHash(t *testing.T) {
	error := hashTest(true)
	if error != nil {
		t.Error(error)
	}
	fmt.Printf("[Hash test] done!\n")
}

func BenchmarkHash(t *testing.B) {
	for i := 0; i < t.N; i++ {
		hashTest(false)
	}
}

func hashTest(ifPrint bool) error {
	var sm guomi.Hashable
	sm = new(guomi.Sm)
	data := "Jingtum Blockchain Guomi Module"
	expectedHash := "a131b88817e7aac559f0a05c7650dbce8c39585586eb62a4af3f47b76f55487e"
	hash := sm.Hash([]byte(data))
	compareResult := guomi.StringToBigInt(expectedHash).String() == guomi.BytesToBigInt(hash).String()
	if ifPrint {
		fmt.Printf("[Hash test] data is: %s\n", data)
		fmt.Printf("[Hash test] digest value is: %x\n", hash)
		fmt.Printf("[Hash test] is hash correct? %t\n", compareResult)
		fmt.Printf("\n")
	}
	if !compareResult {
		return errors.New("The real hash and expected hash do not match!")
	}
	return nil
}

//endregion

//region generate key

func TestGenerate(t *testing.T) {
	error := generateTest(true)
	if error != nil {
		t.Error(error)
	}
	fmt.Printf("[GenerateKey test] done!\n")
}

func BenchmarkGenerate(t *testing.B) {
	for i := 0; i < t.N; i++ {
		generateTest(false)
	}
}

func generateTest(ifPrint bool) error {
	var sm guomi.Cryptable
	sm = new(guomi.Sm)

	seedString := "1234567890123456789012345678901234567890"
	seedPrivateKey := "c839b08ae01313b012bd70594b313446925d243a2eda8522dc99442af2672680"
	seed := guomi.StringToBytes(seedString)

	privateKey, publicKey, err := sm.Generate(seed) // 生成密钥对
	if err != nil {
		log.Fatal(err)
	}
	compareResult := guomi.StringToBigInt(seedPrivateKey).String() == guomi.BytesToBigInt(privateKey).String()
	privateKeyObject := guomi.BytesToPrivateKey(privateKey)
	priv2String := guomi.PrivateKeyToBytes(privateKeyObject)
	priv2 := guomi.BytesToPrivateKey(priv2String)
	if err != nil {
		log.Fatal(err)
	}
	pubBytes := guomi.PublicKeyToBytes(&privateKeyObject.PublicKey)
	pubRes := guomi.BytesToPublicKey(pubBytes)

	if ifPrint {
		fmt.Printf("[GenerateKey Test] seed:%x\n", seedString)
		fmt.Printf("[GenerateKey Test] privateKey should be:%v\n", seedPrivateKey)
		fmt.Printf("[GenerateKey Test] real privateKey:%x\n", privateKey)
		fmt.Printf("[GenerateKey Test] real publicKey:%x\n", publicKey)
		fmt.Printf("[GenerateKey Test] is privateKey correct? %t\n", compareResult)
		fmt.Printf("[GenerateKey Test] privateKey length: %v\n", len(privateKey))
		fmt.Printf("[GenerateKey Test] publicKey length: %v\n", len(publicKey))
		fmt.Printf("\n")

		fmt.Printf("[GenerateKey Test] privateKey object: %x\n", privateKeyObject)
		fmt.Printf("[GenerateKey Test] privateKey.D: %x\n", privateKeyObject.D)
		fmt.Printf("[GenerateKey Test] PublicKey.Curve: %x\n", privateKeyObject.PublicKey.Curve)
		fmt.Printf("[GenerateKey Test] PublicKey.X: %x\n", privateKeyObject.PublicKey.X)
		fmt.Printf("[GenerateKey Test] PublicKey.Y: %x\n", privateKeyObject.PublicKey.Y)
		fmt.Printf("\n")

		fmt.Printf("[GenerateKey Test] convert privateKey object to bytes: %x\n", priv2String)
		fmt.Printf("[GenerateKey Test] convert bytes to privateKey object: %x\n", priv2)

		fmt.Printf("[GenerateKey Test] convert publicKey object to bytes: %x\n", pubBytes)
		fmt.Printf("[GenerateKey Test] publicKey bytes length: %v\n", len(pubBytes))

		fmt.Printf("[GenerateKey Test] convert bytes to publicKey object: %#v\n", pubRes)
		fmt.Printf("\n")
	}
	if !compareResult {
		return errors.New("The real hash and expected hash do not match!")
	}
	return nil
}

//endregion

//region sign

func TestSign(t *testing.T) {
	error := signTest(true)
	if error != nil {
		t.Error(error)
	}
	fmt.Printf("[Sign and Verify test] done!\n")
}

func BenchmarkSign(t *testing.B) {
	for i := 0; i < t.N; i++ {
		signTest(false)
	}
}

func signTest(ifPrint bool) error {
	var sm guomi.Cryptable
	sm = new(guomi.Sm)

	seedString := "1234567890123456789012345678901234567890"
	seed := guomi.StringToBytes(seedString)
	privateKey, publicKey, err := sm.Generate(seed)
	privateKeyObject := guomi.BytesToPrivateKey(privateKey)

	msg := []byte("Jingtum Blockchain Guomi Module")
	publicKeyObject := &privateKeyObject.PublicKey
	ciphertxt, err := publicKeyObject.Encrypt(msg)
	if err != nil {
		log.Fatal(err)
	}
	plaintxt, err := privateKeyObject.Decrypt(ciphertxt)
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(msg, plaintxt) {
		log.Fatal("Decrypt text doesn't match raw message!")
	}
	signedTx, err := sm.Sign(privateKey, nil, msg)
	if err != nil {
		log.Fatal(err)
	}
	isok, err := sm.Verify(publicKey, nil, msg, signedTx)
	if err != nil {
		log.Fatal(err)
	}

	if ifPrint {
		fmt.Printf("[Sign and Verify Test] encrypt result: %x\n", ciphertxt)
		fmt.Printf("[Sign and Verify Test] decrypt result: %s\n", plaintxt)
		fmt.Printf("[Sign and Verify Test] signedTx: %x\n", signedTx)
		fmt.Printf("[Sign and Verify Test] Verified: %v\n", isok)
		fmt.Printf("\n")
	}
	if !isok {
		return errors.New("Verify failed!")
	}
	return nil
}

//endregion
