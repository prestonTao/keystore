package kstore

import (
	"bytes"
	"crypto/sha256"
	"errors"

	"github.com/prestonTao/keystore/crypto"
	"golang.org/x/crypto/ripemd160"
)

//Ripemd
func Ripemd160(bs []byte) []byte {
	sh := sha256.Sum256(bs)
	sh = sha256.Sum256(sh[:])
	rp := ripemd160.New()
	rp.Write(sh[:])
	return rp.Sum(nil)
}

//@params password key/chaincode(加密后) iv checkhash
func CheckPass(spass string, seed, skey, scode, siv, cHash []byte, ripemd bool) (bool, error) {
	//验证密码是否正确
	pwd := sha256.Sum256([]byte(spass))
	if seed != nil && len(seed) > 0 {
		//解密key
		seedBs, s := crypto.DecryptCBC(seed, pwd[:], siv)
		if s != nil {
			return false, s
		}
		// checkHash := append(keyBs, codeBs...)
		h := sha256.New()
		h.Write(seedBs)
		checkHash := h.Sum(pwd[:])
		var ocheckHash []byte
		if ripemd {
			ocheckHash = Ripemd160(checkHash)
		} else {
			ocheckHash = checkHash
		}
		if bytes.Equal(ocheckHash, cHash) {
			return true, nil
		} else {
			return false, errors.New("password error")
		}
	}

	//解密key
	keyBs, s := crypto.DecryptCBC(skey, pwd[:], siv)
	if s != nil {
		return false, s
	}
	//解密chaincode
	codeBs, ss := crypto.DecryptCBC(scode, pwd[:], siv)
	if ss != nil {
		return false, ss
	}
	checkHash := append(keyBs, codeBs...)
	h := sha256.New()
	h.Write(checkHash)
	checkHash = h.Sum(pwd[:])
	var ocheckHash []byte
	if ripemd {
		ocheckHash = Ripemd160(checkHash)
	} else {
		ocheckHash = checkHash
	}
	if bytes.Equal(ocheckHash, cHash) {
		return true, nil
	} else {
		return false, errors.New("password error")
	}
}

type TData struct {
	Status int    `json:"status"`
	Data   []Item `json:"data"`
}
type Item struct {
	Addr      string
	Txid      string
	Value     uint64
	VoutIndex uint64
	VoteType  uint16
	Height    uint64
}

//解析txitem
// func ParseTxItems(jsonstr string) ([]*mining.TxItem, error) {
// 	tdata := TData{}
// 	// err := json.Unmarshal([]byte(jsonstr), &tdata)
// 	decoder := json.NewDecoder(bytes.NewBuffer([]byte(jsonstr)))
// 	decoder.UseNumber()
// 	err := decoder.Decode(&tdata)
// 	if err != nil {
// 		fmt.Println(err)
// 		return nil, err
// 	}
// 	//fmt.Printf("%+v", tdata)
// 	var txitem []*mining.TxItem
// 	for _, val := range tdata.Data {
// 		addr := crypto.AddressFromB58String(val.Addr)
// 		txid, _ := hex.DecodeString(val.Txid)
// 		it := &mining.TxItem{Height: val.Height, Addr: &addr, Txid: txid, Value: val.Value, VoutIndex: val.VoutIndex, VoteType: val.VoteType}
// 		txitem = append(txitem, it)
// 	}
// 	//fmt.Printf("%+v", txitem[0])
// 	return txitem, nil
// }

//解析交易
// func ParseTxItr(bs []byte) (mining.TxItr, error) {
// 	return mining.ParseTxBase(&bs)
// 	// tx := mining.Tx_Pay{}
// 	// err := json.Unmarshal(bs, &tx)
// 	// return tx, err
// }

//验证待签名数据是否正确
func ParseAddrData(jsonstr string) (map[string]uint64, error) {
	mp := make(map[string]uint64)
	// err := json.Unmarshal([]byte(jsonstr), &mp)
	decoder := json.NewDecoder(bytes.NewBuffer([]byte(jsonstr)))
	decoder.UseNumber()
	err := decoder.Decode(&mp)
	if err != nil {
		return nil, err
	}
	return mp, nil
}

//验证待签名数据是否正确
//addrdata {"XXXX":1000,"YYYYY":2000}
// func CheckAddrData(addrdata map[string]uint64, vout *[]mining.Vout, returnaddr crypto.AddressCoin) bool {
// 	if len(*vout) == 0 || len(addrdata) == 0 {
// 		//fmt.Println("0000", len(*vout), len(addrdata))
// 		return false
// 	}
// 	for _, val := range *vout {
// 		//如果是退款地址，单独验证，这里退出
// 		if bytes.Equal(val.Address, returnaddr) {
// 			continue
// 		}
// 		addr := val.Address
// 		if addrdata[addr.B58String()] != val.Value {
// 			//fmt.Println("2222", addrdata, addr.B58String(), val.Value)
// 			return false
// 		}
// 	}
// 	//vout数量多于1个，则数据错误,因为最多多一个找零地址
// 	if len(*vout)-len(addrdata) > 1 || len(*vout)-len(addrdata) < 0 {
// 		//fmt.Println("3333", len(*vout), len(addrdata))
// 		return false
// 	}
// 	//如果vout数量与转出地址数量不一致，则判断找零地址是否存在
// 	if len(*vout)-len(addrdata) == 1 {
// 		var returnaddrbool bool
// 		for _, val := range *vout {
// 			if bytes.Equal(val.Address, returnaddr) {
// 				//fmt.Println("111", val.Address, returnaddr.B58String())
// 				returnaddrbool = true
// 				continue
// 			}
// 		}
// 		if !returnaddrbool {
// 			return false
// 		}
// 	}
// 	return true
// }
