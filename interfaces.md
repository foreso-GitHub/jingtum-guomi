- [Jingtum Guomi Module Interface](#guomi-module)
  - [Hashable 接口](#Hashable-interface)
    * [Hash](#Hashable-Hash-method)
  - [Cryptable 接口](#Cryptable-interface)
    * [Generate](#Cryptable-Generate-method)
    * [Sign](#Cryptable-Sign-method)
    * [Verify](#Cryptable-Verify-method)
    
## <a name="guomi-module"><a name="guomi-module"></a>国密模块接口

#### <a name="Hashable-interface"></a>Hashable 接口

生成符合国密sm3标准的密码杂凑

```js
type Hashable interface {
	// return the hash bytes of the given msg bytes
	Hash(msg []byte) []byte
}
```

#### <a name="Hashable-Hash-method"></a>Hash 根据给定的信息，生成对应的密码杂凑（hash）

返回给定给定的信息对应的密码杂凑（hash）

##### Parameters 参数

1. `[]byte` - 需要生成密码杂凑的信息


##### Returns 返回值

`[]byte` - 给定信息对应的密码杂凑


##### Example 例子
```go
func hashExample() {
	var sm guomi.Hashable
	sm = new(guomi.Sm)
	data := "Jingtum Blockchain Guomi Module"
	expectedHash := "a131b88817e7aac559f0a05c7650dbce8c39585586eb62a4af3f47b76f55487e"
	hash := sm.Hash([]byte(data))
	fmt.Printf("[Hash test] data is: %s\n", data)
	fmt.Printf("[Hash test] digest value is: %x\n", hash)
	fmt.Printf("[Hash test] is hash correct? %t\n",
		guomi.StringToBigInt(expectedHash).String() == guomi.BytesToBigInt(hash).String())
	fmt.Printf("\n")
}
```

***


#### <a name="Cryptable-interface"></a>Cryptable 接口

生成符合国密sm2标准的密钥对，提供符合国密sm2标准的非对称加密算法

```js
type Cryptable interface {
	// generate public key and private key from given seed
	Generate(seed []byte) ([]byte, []byte, error)

	// sign the given hash of the msg, or from msg by private key
	Sign(privateKey []byte, hash []byte, msg []byte) ([]byte, error)

	// verify the given signature and hash of the msg, or from msg by public key
	Verify(publicKey []byte, hash []byte, msg []byte, signature []byte) (bool, error)
}
```

#### <a name="Cryptable-Generate-method"></a>Generate 生成密钥对

返回符合国密sm2标准的密钥对，包括私钥和公钥

##### Parameters 参数

1. `seed []byte` - 需要生成密钥对的种子信息

##### Returns 返回值

1. `[]byte` - 私钥
2. `[]byte` - 公钥
3. `error` - 出错信息

##### Example 例子
```go
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
```

***

#### <a name="Cryptable-Sign-method"></a>Sign 签名

用给定的私钥签名给定的信息

##### Parameters 参数

1. `privateKey []byte` - 私钥
2. `hash []byte` - 需要签名的信息的hash（和msg只能二选一）
3. `msg []byte` - 需要签名的信息（和hash只能二选一）

##### Returns 返回值

1. `[]byte` - 签名后的信息
2. `error` - 出错信息


##### Example 例子
```go
msg := []byte("Jingtum Blockchain Guomi Module")
signedTx, err := sm.Sign(privateKey, nil, msg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[GenerateKey Test] signedTx: %x\n", signedTx)
```

***

#### <a name="Cryptable-Verify-method"></a>Verify 验证签名

验证签名信息

##### Parameters 参数

1. `publicKey []byte` - 私钥
2. `hash []byte` - 需要验证的信息的hash（和msg只能二选一）
3. `msg []byte` - 需要验证的信息（和hash只能二选一）
4. `signature []byte` - 需要验证的签名信息

##### Returns 返回值

1. `bool` - 是否验证成功
2. `error` - 出错信息


##### Example 例子
```go
isok, err := sm.Verify(publicKey, nil, msg, signedTx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[GenerateKey Test] Verified: %v\n", isok)
```

***


