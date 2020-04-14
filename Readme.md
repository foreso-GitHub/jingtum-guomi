井通区块链国密模块

接口：
```js
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
```