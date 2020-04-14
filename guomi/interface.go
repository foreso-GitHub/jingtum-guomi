package guomi

import (
	"../gmsm/sm2"
	"../gmsm/sm3"
	"crypto/elliptic"
	"errors"
	"log"
	"math/big"
)

//region interfaces

type Cryptable interface {
	// generate public key and private key from given seed
	Generate(seed []byte) ([]byte, []byte, error)

	// sign the given hash of the msg, or from msg by private key
	Sign(privateKey []byte, hash []byte, msg []byte) ([]byte, error)

	// verify the given signature and hash of the msg, or from msg by public key
	Verify(publicKey []byte, hash []byte, msg []byte, signature []byte) (bool, error)
}

type Hashable interface {
	// return the hash bytes of the given msg bytes
	Hash(msg []byte) []byte
}

//endregion

//region struct
type Sm struct {
}

var one = new(big.Int).SetInt64(1)

//endregion

//region hash

func (sm Sm) Hash(msg []byte) []byte {
	return Sm3Hash(msg)
}

func Sm3Hash(msg []byte) []byte {
	h := sm3.New()
	h.Write(msg)
	result := h.Sum(nil)
	return result
}

//endregion

//region generate key

//region key process

func RestorePrivateKey(k *big.Int) *sm2.PrivateKey {
	c := sm2.P256Sm2()
	privateKey := new(sm2.PrivateKey)
	privateKey.PublicKey.Curve = c
	privateKey.D = k
	privateKey.PublicKey.X, privateKey.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return privateKey
}

func RestorePublicKey(x *big.Int, y *big.Int) *sm2.PublicKey {
	c := sm2.P256Sm2()
	publicKey := new(sm2.PublicKey)
	publicKey.Curve = c
	publicKey.X = x
	publicKey.Y = y
	return publicKey
}

func PrivateKeyToBytes(privateKey *sm2.PrivateKey) []byte {
	return BigIntToBytes(privateKey.D)
}

func BytesToPrivateKey(bytes []byte) *sm2.PrivateKey {
	k := BytesToBigInt(bytes)
	return RestorePrivateKey(k)
}

func PublicKeyToBytes(publicKey *sm2.PublicKey) []byte {
	xBytes := BigIntToBytes(publicKey.X)
	yBytes := BigIntToBytes(publicKey.Y)
	bytes := append(xBytes, yBytes...)
	return bytes
}

func BytesToPublicKey(bytes []byte) *sm2.PublicKey {
	size := 32
	xBytes := bytes[:size]
	yBytes := bytes[size:]
	x := BytesToBigInt(xBytes)
	y := BytesToBigInt(yBytes)
	return RestorePublicKey(x, y)
}

//endregion

//region basic utility

func BigIntToBytes(n *big.Int) []byte {
	return n.Bytes()
}

func BytesToBigInt(bytes []byte) *big.Int {
	return new(big.Int).SetBytes(bytes)
}

func BigIntToString(n *big.Int) string {
	return n.String()
}

func StringToBigInt(str string) *big.Int {
	n, ok := new(big.Int).SetString(str, 16)
	if !ok {
		log.Fatal("StringToBigInt error!")
	}
	return n
}

func StringToBytes(str string) []byte {
	return []byte(str)
}

func BytesToString(bytes []byte) string {
	return string(bytes[:])
}

//endregion

//region generate

func (sm Sm) Generate(seed []byte) ([]byte, []byte, error) {
	hash := Sm3Hash(seed)
	privateKey, err := GenerateKey(hash)
	if err != nil {
		log.Fatal(err)
	}
	privateKeyBytes := PrivateKeyToBytes(privateKey)
	publicKeyBytes := PublicKeyToBytes(&privateKey.PublicKey)
	return privateKeyBytes, publicKeyBytes, err
}

func GenerateKey(seed []byte) (*sm2.PrivateKey, error) {
	c := sm2.P256Sm2()
	k, err := randFieldElementBySeed(c, seed)
	if err != nil {
		return nil, err
	}
	priv := new(sm2.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

func randFieldElementBySeed(c elliptic.Curve, seed []byte) (k *big.Int, err error) {
	params := c.Params()
	b := seed
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

//endregion

//endregion

//region sign

func (sm Sm) Sign(privateKey []byte, hash []byte, msg []byte) ([]byte, error) {
	//var input = []byte("")
	//if hash != nil && msg != nil{
	//	return nil, errors.New("Both hash and msg exists!")
	//} else if hash != nil && msg == nil{
	//	input = hash
	//} else if hash == nil && msg != nil{
	//	input = msg
	//} else {
	//	return nil, errors.New("Neither hash nor msg exists!")
	//}

	input, err := SelectInput(hash, msg)
	if err != nil {
		return nil, err
	}
	privateKeyObject := BytesToPrivateKey(privateKey)
	r, s, err := sm2.Sign(privateKeyObject, input)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	signedTx, err := sm2.SignDigitToSignData(r, s)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	return signedTx, nil
}

func (sm Sm) Verify(publicKey []byte, hash []byte, msg []byte, signature []byte) (bool, error) {
	//var input = []byte("")
	//if hash != nil && msg != nil{
	//	return false, errors.New("Both hash and msg exists!")
	//} else if hash != nil && msg == nil{
	//	input = hash
	//} else if hash == nil && msg != nil{
	//	input = msg
	//} else {
	//	return false, errors.New("Neither hash nor msg exists!")
	//}

	input, err := SelectInput(hash, msg)
	if err != nil {
		return false, err
	}
	publicKeyObject := BytesToPublicKey(publicKey)
	r, s, err := sm2.SignDataToSignDigit(signature)
	if err != nil {
		log.Fatal(err)
		return false, err
	}
	result := sm2.Verify(publicKeyObject, input, r, s)
	return result, nil
}

func SelectInput(hash []byte, msg []byte) ([]byte, error) {
	var input = []byte("")
	if hash != nil && msg != nil {
		return nil, errors.New("Both hash and msg exists!")
	} else if hash != nil && msg == nil {
		input = hash
	} else if hash == nil && msg != nil {
		input = msg
	} else {
		return nil, errors.New("Neither hash nor msg exists!")
	}
	return input, nil
}

//endregion
