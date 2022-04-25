package main

import (
	"fmt"
	"path/filepath"

	"keystore"
)

func main() {
	fmt.Println("start")

	filePath := filepath.Join("conf", "key.txt")
	err := keystore.Load(filePath)
	fmt.Println("load error:", err)
	if err == nil {
		return
	}
	err = keystore.CreateKeystore(filePath, "13579246810")
	fmt.Println("CreateKeystore error:", err)

}
