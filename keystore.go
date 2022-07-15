package keystore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"strconv"
	"sync"

	"github.com/prestonTao/keystore/crypto"
	"golang.org/x/crypto/hkdf"
)

type Keystore struct {
	filepath string        //keystore文件存放路径
	Wallets  []*Wallet     `json:"wallets"`  //keystore中的所有钱包
	Coinbase uint64        `json:"coinbase"` //当前默认使用的收付款地址
	DHIndex  uint64        `json:"dhindex"`  //DH密钥，指向钱包位置
	lock     *sync.RWMutex //
}

func NewKeystore(filepath string) *Keystore {
	keys := Keystore{
		filepath: filepath,          //keystore文件存放路径
		lock:     new(sync.RWMutex), //
	}
	return &keys
}

/*
	从磁盘文件加载keystore
*/
func (this *Keystore) Load() error {
	// var keystore Keystore
	bs, err := ioutil.ReadFile(this.filepath)
	if err != nil {
		return err
	}
	//fmt.Println(string(bs))

	// err = json.Unmarshal(bs, &this.Wallets)
	decoder := json.NewDecoder(bytes.NewBuffer(bs))
	decoder.UseNumber()
	err = decoder.Decode(&this.Wallets)
	if err != nil {
		return err
	}
	if len(this.Wallets) <= 0 {
		//钱包文件损坏:钱包个数为0
		return errors.New("Damaged wallet file: the number of wallets is 0")
	}
	for i, _ := range this.Wallets {
		walletOne := this.Wallets[i]
		walletOne.lock = new(sync.RWMutex)
		walletOne.addrMap = new(sync.Map)
		walletOne.pukMap = new(sync.Map)
		if !walletOne.CheckIntact() {
			//钱包文件损坏:第" + strconv.Itoa(i+1) + "个钱包不完整
			return errors.New("Damaged wallet file: No" + strconv.Itoa(i+1) + "Wallet incomplete")
		}
		// if walletOne.Seed != nil && len(walletOne.Seed) > 0 {
		// 	walletOne.IV = salt
		// }

		for j, one := range walletOne.Addrs {
			addrInfo := walletOne.Addrs[j]
			addrStr := one.Addr.B58String()
			addrInfo.AddrStr = addrStr

			walletOne.addrMap.Store(addrStr, addrInfo)
			walletOne.pukMap.Store(hex.EncodeToString(one.Puk), addrInfo)
		}
	}
	return nil
}

/*
	从磁盘文件加载keystore
*/
func (this *Keystore) Save() error {
	// engine.Log.Info("v%", this.Wallets)

	newWallets := make([]*Wallet, 0)
	for _, one := range this.Wallets {
		walletOne := Wallet{
			Seed:      one.Seed,      //种子
			Key:       one.Key,       //生成主密钥的随机数
			ChainCode: one.ChainCode, //主KDF链编码
			IV:        one.IV,        //aes加密向量
			CheckHash: one.CheckHash, //主私钥和链编码加密验证hash值
			Coinbase:  one.Coinbase,  //当前默认使用的收付款地址
			Addrs:     one.Addrs,     //已经生成的地址列表
			DHKey:     one.DHKey,     //DH密钥
		}
		if one.Seed != nil && len(one.Seed) > 0 {
			walletOne.Key = nil
			walletOne.ChainCode = nil
		} else {
			walletOne.Seed = nil
		}
		newWallets = append(newWallets, &walletOne)
	}

	bs, err := json.Marshal(newWallets)
	if err != nil {
		return err
	}
	// engine.Log.Info(string(bs))
	return SaveFile(this.filepath, &bs)
}

/*
	创建一个新的种子文件
*/
func (this *Keystore) CreateNewWallet(password [32]byte) error {
	seed, err := crypto.Rand32Byte()
	if err != nil {
		return err
	}
	seedBs := seed[:]

	// key, err := crypto.Rand32Byte()
	// if err != nil {
	// 	return err
	// }
	// chainCode, err := crypto.Rand32Byte()
	// if err != nil {
	// 	return err
	// }
	// iv, err := crypto.Rand16Byte()
	// if err != nil {
	// 	return err
	// }

	// fmt.Println("创建的随机数长度", len(key), len(chainCode), len(iv))

	wallet, err := NewWallet(&seedBs, nil, nil, nil, &password)
	if err != nil {
		return err
	}
	this.lock.Lock()
	this.Wallets = append(this.Wallets, wallet)
	this.lock.Unlock()
	return nil
}

/*
	使用随机数创建一个新的种子文件
*/
func (this *Keystore) CreateNewWalletRand(seedSrc, rand1, rand2 []byte, password [32]byte) error {

	var wallet *Wallet
	var err error
	if seedSrc != nil && len(seedSrc) > 0 {
		// var seed [32]byte
		// copy(seed[:], seedSrc)
		wallet, err = NewWallet(&seedSrc, nil, nil, nil, &password)
	} else {
		var key, chainCode [32]byte
		var iv [16]byte

		r := hkdf.New(sha256.New, rand1, rand2, []byte("rsZUpEuXUqqwXBvSy3EcievAh4cMj6QL"))
		buf := make([]byte, 96)
		_, _ = io.ReadFull(r, buf)
		copy(key[:], buf[:32])
		copy(chainCode[:], buf[32:64])
		copy(iv[:], buf[64:80])
		wallet, err = NewWallet(nil, &key, &chainCode, &iv, &password)
	}

	// pwd := sha256.Sum256(rand)

	// fmt.Println("创建的随机数长度", len(key), len(chainCode), len(iv))

	if err != nil {
		return err
	}
	this.lock.Lock()
	this.Wallets = append(this.Wallets, wallet)
	this.lock.Unlock()
	return nil
}

/*
	获取地址列表
*/
func (this *Keystore) GetAddr() (addrs []*AddressInfo) {
	return this.Wallets[this.Coinbase].GetAddr()
}

/*
	获取网络地址
*/
func (this *Keystore) GetNetAddrPuk(password string) (prk ed25519.PrivateKey, puk ed25519.PublicKey, err error) {
	pwd := sha256.Sum256([]byte(password))
	wallet := this.Wallets[this.Coinbase]
	addr := wallet.GetCoinbase()
	// addr := this.GetCoinbase()
	_, prk, puk, err = wallet.GetKeyByAddr(addr.Addr, pwd)
	return
}
