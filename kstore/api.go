package kstore

import (
	"github.com/prestonTao/keystore"
)

//export wallet
//@params password
func Export(pass string) string {
	ks := keystore.GetKeyStore()
	var seeds []Seed
	for _, val := range ks.Wallets {
		//fmt.Printf("%+v", val)
		//验证密码是否正确
		ok, err := CheckPass(pass, val.Seed, val.Key, val.ChainCode, val.IV, val.CheckHash, false)
		if !ok {
			return Out(500, err.Error())
		}
		sd := Seed{Seed: val.Seed, Key: val.Key, ChainCode: val.ChainCode, IV: val.IV, CheckHash: Ripemd160(val.CheckHash), Index: len(val.Addrs)}
		seeds = append(seeds, sd)
	}
	s := Encode(seeds)
	//fmt.Println(s)
	return Out(200, s)
}

//import wallet
//@param path password seed
func Import(path, password, seed, pre string) string {
	keystore.SetAddrPre(pre)
	ss, err := Decode(seed)
	if err != nil {
		return Out(500, err.Error())
	}
	//fmt.Printf("%+v", ss)
	err = SeedtoFile(path, password, ss)
	if err != nil {
		return Out(500, err.Error())
	}
	return Out(200, "successful")
}
