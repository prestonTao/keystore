package keystore

import (
	"crypto/sha256"
	"fmt"

	jsoniter "github.com/json-iterator/go"
	"github.com/prestonTao/keystore/crypto"
	"golang.org/x/crypto/ed25519"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

var keystoreStatic *Keystore

/*
	加载种子
*/
func Load(fileAbsPath, addrPre string) error {
	addrPreStatic = addrPre
	store := NewKeystore(fileAbsPath)
	err := store.Load()
	if err != nil {
		return err
	}
	keystoreStatic = store
	return nil
}

/*
	创建一个新的keystore
*/
func CreateKeystore(fileAbsPath, addrPre, password string) error {
	addrPreStatic = addrPre
	ks := NewKeystore(fileAbsPath)
	pwd := sha256.Sum256([]byte(password))
	err := ks.CreateNewWallet(pwd)
	if err != nil {
		return err
	}
	err = ks.Save()
	if err != nil {
		return err
	}
	keystoreStatic = ks
	return nil
}

/*
	使用随机数创建一个新的keystore
*/
func CreateKeystoreRand(fileAbsPath string, seed, rand1, rand2 []byte, password string) error {

	// rand1Bs := sha256.Sum256([]byte(rand1))
	// rand2Bs := sha256.Sum256([]byte(rand2))
	pwd := sha256.Sum256([]byte(password))

	ks := NewKeystore(fileAbsPath)
	err := ks.CreateNewWalletRand(seed, rand1, rand2, pwd)
	if err != nil {
		return err
	}
	err = ks.Save()
	if err != nil {
		return err
	}
	keystoreStatic = ks
	return nil
}

// //设置新的种子
// func NewLoad(seed, password string) error {
// 	pass := md5.Sum([]byte(password))
// 	seedData, err := Encrypt([]byte(seed), pass[:])
// 	if err != nil {
// 		return err
// 	}
// 	seeds := Seed{Data: seedData}
// 	NWallet.SetSeed(seeds)
// 	NWallet.SaveSeed(NWallet.Seeds)
// 	NWallet.SetSeedIndex(0)
// 	//创建矿工地址
// 	NWallet.GetNewAddress(pass[:])
// 	return nil
// }

/*
	获取钱包地址列表，不包括导入的钱包地址
*/
func GetAddr() []*AddressInfo {
	return keystoreStatic.GetAddr()
}

/*
	获取本钱包的网络地址
*/
func GetNetAddr(pwd string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	return keystoreStatic.GetNetAddrPuk(pwd)
}

/*
	获取地址列表，包括导入的钱包地址
*/
func GetAddrAll() []*AddressInfo {
	addrs := make([]*AddressInfo, 0)
	keystoreStatic.lock.RLock()
	for _, one := range keystoreStatic.Wallets {
		addrs = append(addrs, one.GetAddr()...)
	}
	keystoreStatic.lock.RUnlock()
	return addrs
}

//获取一个新的地址
func GetNewAddr(password string) (crypto.AddressCoin, error) {
	pwd := sha256.Sum256([]byte(password))
	w := keystoreStatic.Wallets[keystoreStatic.Coinbase]
	addrCoin, err := w.GetNewAddr(pwd)
	if err != nil {
		return nil, err
	}
	err = keystoreStatic.Save()
	return addrCoin, err
}

//获取基础地址
func GetCoinbase() *AddressInfo {
	wallet := keystoreStatic.Wallets[keystoreStatic.Coinbase]
	return wallet.GetCoinbase()
}

/*
	获取DH公钥
*/
func GetDHKeyPair() DHKeyPair {
	wallet := keystoreStatic.Wallets[keystoreStatic.DHIndex]
	return wallet.GetDHbase()
}

/*
	通过地址获取密钥对
*/
func GetKeyByAddr(addr crypto.AddressCoin, password string) (rand []byte, prk ed25519.PrivateKey, puk ed25519.PublicKey, err error) {
	pwd := sha256.Sum256([]byte(password))
	keystoreStatic.lock.RLock()
	for _, one := range keystoreStatic.Wallets {
		rand, prk, puk, err = one.GetKeyByAddr(addr, pwd)
		if err != nil {
			break
		}
	}
	if len(puk) == 0 {
		// fmt.Println("公钥不存在")
		// fmt.Printf("wallet:%+v", keystoreStatic.Wallets)
	}
	if len(prk) == 0 {
		// fmt.Println("私钥不存在")
		// fmt.Printf("wallet:%+v", keystoreStatic.Wallets)
	}
	keystoreStatic.lock.RUnlock()
	return
}

/*
	通过公钥获取密钥
*/
func GetKeyByPuk(puk []byte, password string) (rand []byte, prk ed25519.PrivateKey, err error) {
	pwd := sha256.Sum256([]byte(password))
	keystoreStatic.lock.RLock()
	for _, one := range keystoreStatic.Wallets {
		rand, prk, err = one.GetKeyByPuk(puk, pwd)
		if err != nil {
			break
		}
	}
	keystoreStatic.lock.RUnlock()
	return
}

/*
	通过地址获取公钥
*/
func GetPukByAddr(addr crypto.AddressCoin) (puk ed25519.PublicKey, ok bool) {
	ok = false
	keystoreStatic.lock.RLock()
	for _, one := range keystoreStatic.Wallets {
		if puk, ok = one.GetPukByAddr(addr); ok {
			break
		}
	}
	keystoreStatic.lock.RUnlock()
	return
}

//设置基础地址
func SetCoinbase(index int) {
	// NWallet.SetCoinbase(index)
}

/*
	钱包中查找地址，判断地址是否属于本钱包
*/
func FindAddress(addr crypto.AddressCoin) (addrInfo AddressInfo, ok bool) {
	ok = false
	keystoreStatic.lock.RLock()
	for _, one := range keystoreStatic.Wallets {
		addrInfo, ok = one.FindAddress(addr)
		if ok {
			break
		}
	}
	keystoreStatic.lock.RUnlock()
	return
}

/*
	钱包中查找公钥是否存在
*/
func FindPuk(puk []byte) (addrInfo AddressInfo, ok bool) {
	ok = false
	keystoreStatic.lock.RLock()
	for _, one := range keystoreStatic.Wallets {
		addrInfo, ok = one.FindPuk(puk)
		if ok {
			break
		}
	}
	keystoreStatic.lock.RUnlock()
	return
}

/*
	签名
*/
func Sign(prk ed25519.PrivateKey, content []byte) []byte {
	if len(prk) == 0 {
		return nil
	}
	return ed25519.Sign(prk, content)
}

/*
	修改钱包密码
*/
func UpdatePwd(oldpwd, newpwd string) (ok bool, err error) {
	oldHash := sha256.Sum256([]byte(oldpwd))
	newHash := sha256.Sum256([]byte(newpwd))
	keystoreStatic.lock.RLock()
	for _, one := range keystoreStatic.Wallets {
		ok, err = one.UpdatePwd(oldHash, newHash)
		if err != nil {
			break
		}
		if !ok {
			break
		}
	}
	keystoreStatic.lock.RUnlock()
	err = keystoreStatic.Save()
	return
}

//根据地址获取私钥
// func GetPriKeyByAddress(address, password string) (prikey *ecdsa.PrivateKey, err error) {
// 	// pass := md5.Sum([]byte(password))
// 	// prikey, err = NWallet.GetPriKey(address, pass[:])
// 	// return
// }

//验证地址合法性(Address类型)
// func ValidateAddress(address *crypto.Address) bool {
// 	// validate = NWallet.ValidateAddress(address)
// 	// return
// 	return false
// }

//验证地址合法性(Addres类型)
// func ValidateByAddress(address string) bool {
// 	// validate = NWallet.ValidateByAddress(address)
// 	// return
// 	return false
// }

//获取某个地址的扩展地址
// func GetNewExpAddr(preAddress *Address) *utils.Multihash {
// 	// addr := NWallet.GetNewExpAddress(preAddress)
// 	// return addr
// }

//根据公钥生成地址multihash
// func BuildAddrByPubkey(pub []byte) (*utils.Multihash, error) {
// 	// addr, err := buildAddrinfo(pub, Version)
// 	// return addr, err
// }

func Println() {
	bs, _ := json.Marshal(keystoreStatic)

	fmt.Println("keystore\n", string(bs))
}

//export keystore
func GetKeyStore() *Keystore {
	return keystoreStatic
}
