package main

import (
	"./guomi"
	"bytes"
	"fmt"
	"log"
)

func main() {
	hashExample()
	generateExample()
}

func hashExample() {
	var sm guomi.Hashable
	sm = new(guomi.Sm)
	data := "Jingtum Blockchain Guomi Module"
	expectedhash := "a131b88817e7aac559f0a05c7650dbce8c39585586eb62a4af3f47b76f55487e"
	hash := sm.Hash([]byte(data))
	fmt.Printf("[Hash test] data is: %s\n", data)
	fmt.Printf("[Hash test] digest value is: %x\n", hash)
	fmt.Printf("[Hash test] is hash correct? %t\n",
		guomi.StringToBigInt(expectedhash).String() == guomi.BytesToBigInt(hash).String())
	fmt.Printf("\n")
}

func generateExample() {
	var sm guomi.Cryptable
	sm = new(guomi.Sm)

	seedString := "1234567890123456789012345678901234567890"
	seedPrivateKey := "c839b08ae01313b012bd70594b313446925d243a2eda8522dc99442af2672680"
	seed := guomi.StringToBytes(seedString)

	privateKey, publicKey, err := sm.Generate(seed) // 生成密钥对
	fmt.Printf("[GenerateKey Test] seed:%x\n", seedString)
	fmt.Printf("[GenerateKey Test] privateKey should be:%v\n", seedPrivateKey)
	fmt.Printf("[GenerateKey Test] real privateKey:%x\n", privateKey)
	fmt.Printf("[GenerateKey Test] real publicKey:%x\n", publicKey)
	fmt.Printf("[GenerateKey Test] is privateKey correct? %t\n",
		guomi.StringToBigInt(seedPrivateKey).String() == guomi.BytesToBigInt(privateKey).String())
	fmt.Printf("[GenerateKey Test] privateKey length: %v\n", len(privateKey))
	fmt.Printf("[GenerateKey Test] publicKey length: %v\n", len(publicKey))
	fmt.Printf("\n")

	privateKeyObject := guomi.BytesToPrivateKey(privateKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[GenerateKey Test] privateKey object: %x\n", privateKeyObject)
	fmt.Printf("[GenerateKey Test] privateKey.D: %x\n", privateKeyObject.D)
	fmt.Printf("[GenerateKey Test] PublicKey.Curve: %x\n", privateKeyObject.PublicKey.Curve)
	fmt.Printf("[GenerateKey Test] PublicKey.X: %x\n", privateKeyObject.PublicKey.X)
	fmt.Printf("[GenerateKey Test] PublicKey.Y: %x\n", privateKeyObject.PublicKey.Y)
	fmt.Printf("\n")

	priv2String := guomi.PrivateKeyToBytes(privateKeyObject)
	fmt.Printf("[GenerateKey Test] convert privateKey object to bytes: %x\n", priv2String)
	priv2 := guomi.BytesToPrivateKey(priv2String)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[GenerateKey Test] convert bytes to privateKey object: %x\n", priv2)
	pubBytes := guomi.PublicKeyToBytes(&privateKeyObject.PublicKey)
	fmt.Printf("[GenerateKey Test] convert publicKey object to bytes: %x\n", pubBytes)
	fmt.Printf("[GenerateKey Test] publicKey bytes length: %v\n", len(pubBytes))
	pubRes := guomi.BytesToPublicKey(pubBytes)
	fmt.Printf("[GenerateKey Test] convert bytes to publicKey object: %#v\n", pubRes)
	fmt.Printf("\n")

	msg := []byte("Jingtum Blockchain Guomi Module")
	publicKeyObject := &privateKeyObject.PublicKey
	ciphertxt, err := publicKeyObject.Encrypt(msg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[GenerateKey Test] encrypt result: %x\n", ciphertxt)
	plaintxt, err := privateKeyObject.Decrypt(ciphertxt)
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(msg, plaintxt) {
		log.Fatal("Decrypt text doesn't match raw message!")
	}
	fmt.Printf("[GenerateKey Test] decrypt result: %s\n", plaintxt)

	signedTx, err := sm.Sign(privateKey, nil, msg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[GenerateKey Test] signedTx: %x\n", signedTx)
	isok, err := sm.Verify(publicKey, nil, msg, signedTx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[GenerateKey Test] Verified: %v\n", isok)

	fmt.Printf("\n")
}
