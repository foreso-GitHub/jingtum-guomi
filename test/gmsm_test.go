package main

import (
	"../gmsm/sm2"
	"../gmsm/sm3"
	"../gmsm/sm4"
	"../guomi"
	"bytes"
	"crypto/cipher"
	"fmt"
	"log"
	"testing"
)

//func main() {
//	sm2Test()
//	sm3Test()
//	sm4Test()
//}

func TestSm2(t *testing.T) {
	sm2Test(true)
	fmt.Printf("[sm2 test] done!\n")
}

func TestSm3(t *testing.T) {
	sm3Test(true)
	fmt.Printf("[sm3 test] done!\n")
}

func TestSm4(t *testing.T) {
	sm4Test(true)
	fmt.Printf("[sm4 test] done!\n")
}

func BenchmarkSm2(t *testing.B) {
	for i := 0; i < t.N; i++ {
		sm2Test(false)
	}
}

func BenchmarkSm3(t *testing.B) {
	for i := 0; i < t.N; i++ {
		sm3Test(false)
	}
}

func BenchmarkSm4(t *testing.B) {
	for i := 0; i < t.N; i++ {
		sm4Test(false)
	}
}

//region sm2 test

func sm2Test(ifPrint bool) {
	priv, err := sm2.GenerateKey() // 生成密钥对
	if err != nil {
		log.Fatal(err)
	}
	if ifPrint {
		fmt.Printf("[sm2 test] 生成密钥对:%x\n", priv)
		fmt.Printf("")
		fmt.Printf("[sm2 test] priv.D:%x\n", priv.D)
		fmt.Printf("")
		fmt.Printf("[sm2 test] priv.PublicKey:%x\n", priv.PublicKey)
		fmt.Printf("")
		fmt.Printf("[sm2 test] priv.PublicKey.Curve:%x\n", priv.PublicKey.Curve)
		fmt.Printf("")
		fmt.Printf("[sm2 test] priv.PublicKey.X:%x\n", priv.PublicKey.X)
		fmt.Printf("")
		fmt.Printf("[sm2 test] priv.PublicKey.Y:%x\n", priv.PublicKey.Y)
		fmt.Printf("")
	}

	privString := guomi.PrivateKeyToBytes(priv)
	privRes := guomi.BytesToPrivateKey(privString)
	pubString := guomi.PublicKeyToBytes(&priv.PublicKey)
	pubRes := guomi.BytesToPublicKey(pubString)
	if ifPrint {
		fmt.Printf("[sm2 test] privString:%x\n", privString)
		fmt.Printf("[sm2 test] privRes:%#v\n", privRes)
		fmt.Printf("[sm2 test] pubString:%x\n", pubString)
		fmt.Printf("[sm2 test] pubRes:%#v\n", pubRes)
	}

	msg := []byte("Jingtum Blockchain Guomi Module")
	pub := &priv.PublicKey
	ciphertxt, err := pub.Encrypt(msg)
	if err != nil {
		log.Fatal(err)
	}
	plaintxt, err := privRes.Decrypt(ciphertxt)
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(msg, plaintxt) {
		log.Fatal("原文不匹配")
	}
	r, s, err := sm2.Sign(priv, msg)
	if err != nil {
		log.Fatal(err)
	}
	isok := sm2.Verify(pub, msg, r, s)
	signedTx, err := sm2.SignDigitToSignData(r, s)
	if ifPrint {
		fmt.Printf("[sm2 test] 加密结果:%x\n", ciphertxt)
		fmt.Printf("[sm2 test] 解密结果:%s\n", plaintxt)
		fmt.Printf("[sm2 test] signedTx: %x\n", signedTx)
		fmt.Printf("[sm2 test] Verified: %v\n", isok)
	}
}

//endregion

//region sm3 test

func sm3Test(ifPrint bool) {
	//data := "abc"
	data := "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
	//data := "Tongji Fintech Research Institute"
	h := sm3.New()
	h.Write([]byte(data))
	sum := h.Sum(nil)
	if ifPrint {
		fmt.Printf("[sm3 test] data is: %s\n", data)
		fmt.Printf("[sm3 test] digest value is: %x\n", sum)
		fmt.Printf("\n")
	}
}

//endregion

//region sm4 test

func sm4Test(ifPrint bool) {
	// 128比特密钥
	key := []byte("1234567890abcdef")
	// 128比特iv
	//iv := make([]byte, sm4.BlockSize)
	iv := []byte("90abcdef12345678")

	data := []byte("Jingtum Blockchain Guomi Module")
	ciphertxt, err := sm4Encrypt(key, iv, data)
	if err != nil {
		log.Fatal(err)
	}

	rawData, err := sm4Decrypt(key, iv, ciphertxt)
	if err != nil {
		log.Fatal(err)
	}
	if ifPrint {
		fmt.Printf("[sm4 test] key: %s\n", key)
		fmt.Printf("[sm4 test] iv: %x\n", iv)
		fmt.Printf("[sm4 test] 加密结果: %x\n", ciphertxt)
		fmt.Printf("[sm4 test] 解密结果: %s\n", rawData)
		fmt.Printf("\n")
	}
}

func sm4Encrypt(key, iv, plainText []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData := pkcs5Padding(plainText, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	cryted := make([]byte, len(origData))
	blockMode.CryptBlocks(cryted, origData)
	return cryted, nil
}

func sm4Decrypt(key, iv, cipherText []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(cipherText))
	blockMode.CryptBlocks(origData, cipherText)
	origData = pkcs5UnPadding(origData)
	return origData, nil
}

// pkcs5填充
func pkcs5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func pkcs5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

//endregion
