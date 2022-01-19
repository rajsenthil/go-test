//package main
//
//import (
//	"crypto/aes"
//	"crypto/cipher"
//	"crypto/md5"
//	"crypto/rand"
//	"encoding/hex"
//	"fmt"
//	"io"
//	"io/ioutil"
//	"os"
//)
//
//func createHash(key string) string {
//	hasher := md5.New()
//	hasher.Write([]byte(key))
//	return hex.EncodeToString(hasher.Sum(nil))
//}
//
//func encrypt(data []byte, passphrase string) []byte {
//	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
//	gcm, err := cipher.NewGCM(block)
//	if err != nil {
//		panic(err.Error())
//	}
//	nonce := make([]byte, gcm.NonceSize())
//	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
//		panic(err.Error())
//	}
//	ciphertext := gcm.Seal(nonce, nonce, data, nil)
//	return ciphertext
//}
//
//func decrypt(data []byte, passphrase string) []byte {
//	key := []byte(createHash(passphrase))
//	block, err := aes.NewCipher(key)
//	if err != nil {
//		panic(err.Error())
//	}
//	gcm, err := cipher.NewGCM(block)
//	if err != nil {
//		panic(err.Error())
//	}
//	nonceSize := gcm.NonceSize()
//	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
//	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
//	if err != nil {
//		panic(err.Error())
//	}
//	return plaintext
//}
//
//func encryptFile(filename string, data []byte, passphrase string) {
//	f, _ := os.Create(filename)
//	defer f.Close()
//	f.Write(encrypt(data, passphrase))
//}
//
//func decryptFile(filename string, passphrase string) []byte {
//	data, _ := ioutil.ReadFile(filename)
//	return decrypt(data, passphrase)
//}
//
//func main() {
//	fmt.Println("Starting the application...")
//	ciphertext := encrypt([]byte("47JG!@b\"ot"), "eNNavale")
//	fmt.Printf("Encrypted: %x\n", ciphertext)
//	plaintext := decrypt(ciphertext, "eNNavale")
//	fmt.Printf("Decrypted: %s\n", plaintext)
//	//encryptFile("sample.txt", []byte("47JG!@b\"ot"), "eNNavale")
//	//fmt.Println(string(decryptFile("sample.txt", "eNNavale")))
//}

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
)

func encrypt(stringToEncrypt string, keyString string) (encryptedString string) {

	log.Println("Passed Key: ", keyString)
	//Since the key is in string, we need to convert decode it to bytes
	//key, decodeError := hex.DecodeString(keyString)
	//if decodeError != nil {
	//	panic(decodeError.Error())
	//}
	key := []byte(keyString)
	log.Println("Key decoded: ", key)
	plaintext := []byte(stringToEncrypt)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	//https://golang.org/pkg/crypto/cipher/#NewGCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Create a nonce. Nonce should be from GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	//Encrypt the data using aesGCM.Seal
	//Since we don't want to save the nonce somewhere else in this case, we add it as a prefix to the encrypted data. The first nonce argument in Seal is the prefix.
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return fmt.Sprintf("%x", ciphertext)
}

func decrypt(encryptedString string, keyString string) (decryptedString string) {

	//key, _ := hex.DecodeString(keyString)
	key := []byte(keyString)
	enc, _ := hex.DecodeString(encryptedString)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Get the nonce size
	nonceSize := aesGCM.NonceSize()

	//Extract the nonce from the encrypted data
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	//Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return fmt.Sprintf("%s", plaintext)
}

func main() {
	key := os.Args[1]
	log.Println("Key: ", key)
	//encryptedString := encrypt("47JG!@b\"ot", key)
	encryptedString := encrypt("password", key)
	fmt.Println(encryptedString)
	log.Println("Encrypted password: ", encryptedString)
	fmt.Println(decrypt(encryptedString, key))
}
