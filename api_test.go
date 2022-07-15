package keystore

import (
	"fmt"
	"testing"
	// "github.com/prestonTao/keystore/crypto"
)

func TestApi(t *testing.T) {
	example1()
	// leftRecentTest()
}

func example1() {

	path := "key.json"
	addrPre := "TEST"
	pwd := "123"
	err := CreateKeystore(path, addrPre, pwd)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("11111111111111")
	addr, err := GetNewAddr(pwd)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(addr.B58String())

	addrInfos := GetAddrAll()
	for _, one := range addrInfos {
		fmt.Println("遍历地址:", one.Addr.B58String())
	}

	err = Load(path, addrPre)
	if err != nil {
		fmt.Println("加载密钥报错:", err)
	}
	addr, err = GetNewAddr(pwd)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(addr.B58String())

	addrInfos = GetAddrAll()
	for _, one := range addrInfos {
		fmt.Println("遍历地址:", one.Addr.B58String())
	}
}
