package kstore

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"path/filepath"

	jsoniter "github.com/json-iterator/go"
	"github.com/mr-tron/base58"
	"github.com/prestonTao/keystore"
	"github.com/prestonTao/utils"
	"github.com/prestonTao/utils/crypto"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

type KStore struct {
	Path    string
	Keyname string
}

// func NewKStore() *KStore {
// 	return new(KStore)
// }
// func (ks *KStore) SetPath(path string) {
// 	ks.Path = path
// 	ks.Keyname = "key.txt"
// }

//创建钱包
func (ks *KStore) Create(pwd string) error {
	utils.CheckCreateDir(ks.Path)
	fileAbsPath := filepath.Join(ks.Path, ks.Keyname)
	exist, err := utils.PathExists(fileAbsPath)
	if err != nil {
		return err
	}
	if exist {
		err := keystore.Load(fileAbsPath, keystore.GetAddrPre())
		if err != nil {
			return err
		}
	} else {
		err = keystore.CreateKeystore(fileAbsPath, keystore.GetAddrPre(), pwd)
		if err != nil {
			return err
		}
	}
	return nil
}

//编码种子
func Encode(seed interface{}) string {
	bs, err := json.Marshal(seed)
	if err != nil {
		fmt.Println(err)
	}
	s := base58.Encode(bs)
	return s
}

//解码种子
func Decode(s string) ([]Seed, error) {
	bs, err := base58.Decode(s)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	var seeds []Seed
	// err = json.Unmarshal(bs, &seeds)
	decoder := json.NewDecoder(bytes.NewBuffer(bs))
	decoder.UseNumber()
	err = decoder.Decode(&seeds)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return seeds, nil
}

//根据种子生成keystore
func SeedtoFile(path, password string, seed []Seed) error {
	// paths := filepath.Join(path, "key.txt")
	kst := keystore.NewKeystore(path)
	for _, val := range seed {
		//验证密码是否正确
		ok, err := CheckPass(password, val.Seed, val.Key, val.ChainCode, val.IV, val.CheckHash, true)
		if !ok {
			return err
		}
		var iv [16]byte
		copy(iv[:], val.IV)
		pwd := sha256.Sum256([]byte(password))

		if val.Seed != nil && len(val.Seed) > 0 {
			var seed [32]byte
			//解密seed
			seedSrc, s := crypto.DecryptCBC(val.Seed, pwd[:], iv[:])
			if s != nil {
				return s
			}
			copy(seed[:], seedSrc)
			wallet, err := keystore.NewWallet(&seed, nil, nil, nil, &pwd)
			if err != nil {
				fmt.Println(err)
			}
			for i := 0; i < val.Index; i++ {
				wallet.GetNewAddr(pwd)
			}
			kst.Wallets = append(kst.Wallets, wallet)
		} else {

			var key, chaincode [32]byte

			//解密key
			k, s := crypto.DecryptCBC(val.Key, pwd[:], iv[:])
			if s != nil {
				return s
			}
			copy(key[:], k)
			//解密chaincode
			cc, ss := crypto.DecryptCBC(val.ChainCode, pwd[:], iv[:])
			if ss != nil {
				return ss
			}
			copy(chaincode[:], cc)
			wallet, err := keystore.NewWallet(nil, &key, &chaincode, &iv, &pwd)
			if err != nil {
				fmt.Println(err)
			}
			for i := 0; i < val.Index; i++ {
				wallet.GetNewAddr(pwd)
			}
			kst.Wallets = append(kst.Wallets, wallet)
		}
	}
	return kst.Save()
}
