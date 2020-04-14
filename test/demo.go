package main

import (
	"../gmsm/sm2"
	"../gmsm/sm3"
	"../gmsm/sm4"
	"../guomi"
	"bytes"
	"crypto/cipher"
	"math/big"

	//"encoding/asn1"
	"fmt"
	"log"
)

func main() {
	//sm2Test()
	//sm3Test()
	//sm4Test()

	//hashTest()
	generateTest()

	//tempTest()
}

func tempTest() {
	//var sm guomi.Cryptable
	//sm = new(guomi.Sm)
	kString := "5f076c45e2a79318216e65d69daaddddc82e61ba1c6f5abf4d1aa336c86feada"
	k, ok := big.NewInt(0).SetString(kString, 16)
	if !ok {
		fmt.Printf("[generateTest] kString error!")
	}
	privateKey := guomi.RestorePrivateKey(k) // 生成密钥对
	fmt.Printf("[generateTest] privateKey:%x\n", privateKey)

	privBytes := guomi.PrivateKeyToBytes(privateKey)
	fmt.Printf("[generateTest] privBytes:%x\n", privBytes)

	priv := guomi.BytesToPrivateKey(privBytes)
	fmt.Printf("[generateTest] priv:%x\n", priv)

	pubBytes := guomi.PublicKeyToBytes(&privateKey.PublicKey)
	fmt.Printf("[generateTest] pubBytes:%x\n", pubBytes)

	pub := guomi.BytesToPublicKey(pubBytes)
	fmt.Printf("[generateTest] pub:%x\n", pub)
}

//region Hash test
func hashTest() {
	var sm guomi.Hashable
	sm = new(guomi.Sm)

	//data := "abc"
	//data := "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
	data := "Tongji Fintech Research Institute"
	hash := sm.Hash([]byte(data))
	fmt.Printf("[Hash test] data is: %s\n", data)
	fmt.Printf("[Hash test] digest value is: %x\n", hash)
	fmt.Printf("\n")
}

//endregion

//region generate test
func generateTest() {
	var sm guomi.Cryptable
	sm = new(guomi.Sm)

	//seedString1 := "641256800975030717933389121877709027858604987496584516793868741928776013700668123039110234696336"
	//seedPrivateKey1 := "b8a88c548c50542ae0a240068394d17b074f376a8449efc765c05c0b49bbb66b"
	//seedString1 := "1287651586954262080319231760155412596846011270464548195726696050474863461388858728364632739469812"
	//seedPrivateKey1 := "cfcf1ed7837c8eee587831c04fde470f50411934277e0729138980ce97688d1b"
	//seedString1 := "1708477027019345408659951241387961757649063437767481718850285570033773328072187839580736004211870"
	//seedPrivateKey1 := "0e296fdd8e64b1ce73152f709843c14fe41c5e7cb93f634d48f6c2393a66ea3f"
	//seedString1 := "1708477027019345408659951241387961757649063437767481718850285570033773328072187839580736004211871"
	//seedPrivateKey1 := "0e296fdd8e64b1ce73152f709843c14fe41c5e7cb93f634d48f6c2393a66ea40"

	//seedString1 := "170847702701934540865995124138796175764906343776748171885028557003377332807218783958073600421"
	//seedPrivateKey1 := "2b259b68e303d4748e64b1ce73152f7080558c344921035d7eec69ed3fdb9dca"
	//seedString1 := "1234567890123456789012345678901234567890"  //at least 40 bits
	//seedPrivateKey1 := "9f989b9e3334353652815311574f587b7158f8a1bce0a524c623f7e18278aad9"
	//seedString1 := "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
	//seedPrivateKey1 := "b67c1170dcbe95b8be8290928ef5bbbfb936ce70c7906fa9784d09b881e2f9e9"
	//seedString1 := "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
	//seedPrivateKey1 := "c028abc4fb9a5d77b225c6b0b5e985a96ede5b11a7e68a1bebb86d57ba5a29a9"

	//seedString1 := "12345678901234567890123456789012345"
	//seedPrivateKey1 := "3466686a383930313233343536528152f4474c5bcf74b1411e59b33d8e7c9670"
	//seedString1 := "123456789012345678901234567890123456"
	//seedPrivateKey2 := "66686a6c3930313233343536528153111e82fa0c987834515785abaebd45344f"
	//seedString1 := "1234567890123456789012345678901234567"
	//seedPrivateKey1 := "686a6c9f303132333435365281531157156f07e9034e421428c873103a3c5aac"
	//seedString1 := "12345678901234567890123456789012"
	//seedPrivateKey1 := "3132333435363738393031323334353637383930313233343536373839303133"

	//seedString1 := "1234567890123456789012345678901234567890"
	////seedPrivateKey1 := "9f989b9e3334353652815311574f587b7158f8a1bce0a524c623f7e18278aad9"
	//seedPrivateKey1 := "c839b08ae01313b012bd70594b313446925d243a2eda8522dc99442af2672680"
	//seedString1 := "1234567890123456789012345678901234567891"
	////seedPrivateKey1 := "9f989b9e3334353652815311574f587b7158f8a1bce0a524c623f7e18278aada"
	//seedPrivateKey1 := "3a8420dbaba4afd0b28ed5d619bc28c54b7cc1696afa1c1f45ea763898b13c0e"

	//seedString1 := "123"
	//seedPrivateKey1 := "6e0f9e14344c5406a0cf5a3b4dfb665f87f4a771a31f7edbb5c72874a32b2958"

	//seedString1 := "1"
	//seedPrivateKey1 := "cbdddb8e8421b23498480570d7d75330538a6882f5dfdc3b64115c647f3328c5"
	seedString1 := "2"
	seedPrivateKey1 := "a0dc2d74b9b0e3c87e076003dbfe472a424cb3032463cb339e351460765a822f"

	seed := guomi.StringToBytes(seedString1)
	seedPrivateKey := seedPrivateKey1

	privateKey, publicKey, err := sm.Generate(seed) // 生成密钥对
	fmt.Printf("[generateTest] privateKey:%x\n", privateKey)
	fmt.Printf("[generateTest] pubString:%x\n", publicKey)
	fmt.Printf("[generateTest] seedPrivateKey1:%v\n", seedPrivateKey)
	fmt.Printf("[generateTest] privateKey:%x\n", string(privateKey))
	//a := guomi.StringToBigInt(seedPrivateKey1)
	//b := guomi.BytesToBigInt(privateKey)
	//fmt.Printf("[generateTest] a:%x\n",a)
	//fmt.Printf("[generateTest] b:%x\n",b)
	//fmt.Printf("[generateTest] seedPrivateKey1==privateKey:%t\n", a.String() == b.String())
	fmt.Printf("[generateTest] seedPrivateKey1==privateKey:%t\n",
		guomi.StringToBigInt(seedPrivateKey).String() == guomi.BytesToBigInt(privateKey).String())

	priv := guomi.BytesToPrivateKey(privateKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[generateTest] 生成密钥对:%x\n", priv)
	fmt.Printf("")
	fmt.Printf("[generateTest] priv.D:%x\n", priv.D)
	fmt.Printf("")
	fmt.Printf("[generateTest] priv.PublicKey:%x\n", priv.PublicKey)
	fmt.Printf("")
	fmt.Printf("[generateTest] priv.PublicKey.Curve:%x\n", priv.PublicKey.Curve)
	fmt.Printf("")
	fmt.Printf("[generateTest] priv.PublicKey.X:%x\n", priv.PublicKey.X)
	fmt.Printf("")
	fmt.Printf("[generateTest] priv.PublicKey.Y:%x\n", priv.PublicKey.Y)
	fmt.Printf("")

	priv2String := guomi.PrivateKeyToBytes(priv)
	fmt.Printf("[generateTest] priv2String:%x\n", priv2String)

	priv2 := guomi.BytesToPrivateKey(priv2String)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[generateTest] priv2:%x\n", priv2)

	pubString := guomi.PublicKeyToBytes(&priv.PublicKey)
	fmt.Printf("[generateTest] pubString:%x\n", pubString)

	pubRes := guomi.BytesToPublicKey(pubString)
	fmt.Printf("[generateTest] pubRes:%#v\n", pubRes)

	msg := []byte("Tongji Fintech Research Institute")
	pub := &priv.PublicKey
	ciphertxt, err := pub.Encrypt(msg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[generateTest] 加密结果:%x\n", ciphertxt)

	plaintxt, err := priv.Decrypt(ciphertxt)
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(msg, plaintxt) {
		log.Fatal("原文不匹配")
	}
	fmt.Printf("[generateTest] 解密结果:%s\n", plaintxt)

	signedTx, err := sm.Sign(privateKey, nil, msg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[generateTest] signedTx: %x\n", signedTx)

	isok, err := sm.Verify(publicKey, nil, msg, signedTx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[generateTest] Verified: %v\n", isok)

	fmt.Printf("\n")
}

//endregion

//region sm2 test
func sm2Test() {
	priv, err := sm2.GenerateKey() // 生成密钥对
	if err != nil {
		log.Fatal(err)
	}
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

	//privString, err := asn1.Marshal(priv.D)
	//fmt.Printf("[sm2 test] 密钥:%s\n",priv)

	privString := guomi.PrivateKeyToBytes(priv)
	fmt.Printf("[sm2 test] privString:%x\n", privString)

	privRes := guomi.BytesToPrivateKey(privString)
	fmt.Printf("[sm2 test] privRes:%#v\n", privRes)

	pubString := guomi.PublicKeyToBytes(&priv.PublicKey)
	fmt.Printf("[sm2 test] pubString:%x\n", pubString)

	pubRes := guomi.BytesToPublicKey(pubString)
	fmt.Printf("[sm2 test] pubRes:%#v\n", pubRes)

	msg := []byte("Tongji Fintech Research Institute")
	pub := &priv.PublicKey
	ciphertxt, err := pub.Encrypt(msg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[sm2 test] 加密结果:%x\n", ciphertxt)

	plaintxt, err := privRes.Decrypt(ciphertxt)
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(msg, plaintxt) {
		log.Fatal("原文不匹配")
	}
	fmt.Printf("[sm2 test] 解密结果:%s\n", plaintxt)

	r, s, err := sm2.Sign(priv, msg)
	if err != nil {
		log.Fatal(err)
	}
	isok := sm2.Verify(pub, msg, r, s)
	signedTx, err := sm2.SignDigitToSignData(r, s)
	fmt.Printf("[sm2 test] signedTx: %x\n", signedTx)
	fmt.Printf("[sm2 test] Verified: %v\n", isok)

	fmt.Printf("\n")
}

//endregion

//region sm3 test
func sm3Test() {
	//data := "abc"
	data := "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
	//data := "Tongji Fintech Research Institute"
	h := sm3.New()
	h.Write([]byte(data))
	sum := h.Sum(nil)
	fmt.Printf("[sm3 test] data is: %s\n", data)
	fmt.Printf("[sm3 test] digest value is: %x\n", sum)
	fmt.Printf("\n")
}

//endregion

//region sm4 test
func sm4Test() {
	// 128比特密钥
	key := []byte("1234567890abcdef")
	// 128比特iv
	//iv := make([]byte, sm4.BlockSize)
	iv := []byte("90abcdef12345678")
	fmt.Printf("[sm4 test] key: %s\n", key)
	fmt.Printf("[sm4 test] iv: %x\n", iv)

	data := []byte("Tongji Fintech Research Institute aSdA ASD ASDaw qWE  13	3q2 4q3q234q4 q3")
	ciphertxt, err := sm4Encrypt(key, iv, data)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[sm4 test] 加密结果: %x\n", ciphertxt)

	rawData, err := sm4Decrypt(key, iv, ciphertxt)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[sm4 test] 解密结果: %s\n", rawData)
	fmt.Printf("\n")
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
