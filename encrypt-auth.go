// Copyright 2017 Apoorv Krishak. All rights reserved.
// akrisha1@jhu.edu, apoorv.krishak@gmail.com

/*
	Build Instructions: "go build encrypt-auth.go"
	Usage: "encrypt-auth <mode> -k <32-byte key in hexadecimal> -i <input file> -o <output file>"
*/

package main

import (
	"os"
	"fmt"
	"io/ioutil"
	"crypto/rand"
	"encoding/hex"
	"crypto/sha256"
	"crypto/aes"
)

func showUsage() {
	fmt.Print("\n* AES-CBC Encryption/Decryption Tool *\n\n")
	fmt.Print("An implementation of the cryptographic specifications of AES CBC mode and HMAC\n")
	fmt.Print("\nusage: encrypt-auth <mode> -k <32-byte key in hexadecimal> -i <input file> -o <output file>\n\n")
	fmt.Print("<mode> : encrypt (or) decrypt\n",
	"<32-byte key in hexadecimal> : The first 16 bytes are used as AES Key, and the remaining as HMAC Key. The input should be a 64 character hex string.\n",
	"<input file> : The input file as per the mode - Ex: plainText.txt or cipherText.txt\n",
	"<output file> : The input file as per the mode - Ex: cipherText.txt or recovered_plainText.txt\n")
}

func check(e error) {
	if e != nil {
		showUsage()
		panic(e)
	}
}

func XorBlocks(byteArray1, byteArray2 []byte) []byte {
	xor_result := make([]byte, len(byteArray1))
	for i:=0; i<len(byteArray1); i++ {
		xor_result[i] = byteArray1[i] ^ byteArray2[i]
	}
	return xor_result
}

func hmac_sha256(key_hmac_bytes, message []byte) ([32]byte) {
	BlockSize := 64
	//var key [32]byte
	//key := [32]byte(key_hmac_bytes)
	key := make([]byte, BlockSize) 
	if (len(key_hmac_bytes) > BlockSize) {
		temp := sha256.Sum256(key_hmac_bytes)
		copy(key, temp[:])
		//fmt.Println("HMAC Key: ", key)
	} 
	if (len(key_hmac_bytes) < BlockSize) {
		diff := BlockSize - len(key_hmac_bytes)
		//fmt.Println("\nHMAC Key: ", key, "\nLength: ", len(key))
		for i:=0; i<diff; i++ {
			key = append(key, 0x00)
		}
		//fmt.Println("\nPadded HMAC Key: ", key, "\nLength: ", len(key))
	}

	o_pad := make([]byte, BlockSize)
	for i:=0; i<BlockSize; i++ {
		o_pad[i] = 0x5c
	}

	i_pad := make([]byte, BlockSize)
	for i:=0; i<BlockSize; i++ {
		i_pad[i] = 0x36
	}
	
	o_key_pad := make([]byte, BlockSize)
	i_key_pad := make([]byte, BlockSize)
	o_key_pad = XorBlocks(o_pad, key)
	i_key_pad = XorBlocks(i_pad, key)
	i_key_pad__message := make([]byte, len(i_key_pad) + len(message))
	i_key_pad__message = i_key_pad
	for i:=0; i<len(message); i++ {
		i_key_pad__message = append(i_key_pad__message, message[i])
	}
	hash1 := sha256.Sum256(i_key_pad__message)
	
	o_key_pad__hash1 := make([]byte, len(o_key_pad) + len(hash1))
	o_key_pad__hash1 = o_key_pad
	for i:=0; i<len(hash1); i++ {
		o_key_pad__hash1 = append(o_key_pad__hash1, hash1[i])
	}
	hash2 := sha256.Sum256(o_key_pad__hash1)
	//fmt.Println("HMAC: ", hash2, "Length: ", len(hash2))
	return hash2
}

func Encrypt(plainText []byte, iv []byte, key_enc_bytes []byte, key_hmac_bytes []byte, outputFileName string) {
	AesBlockSize := 16
	//message := string(plainText)
	//fmt.Println("\n\n",plainText, "\n\n", message)
	
	// Calculate the hmac (mac_tag)
	mac_tag := hmac_sha256(key_hmac_bytes, plainText)
	
	// Concatenate: plainText + mac_tag
	for i:=0; i<len(mac_tag); i++ {
		plainText = append(plainText, mac_tag[i])
	}
	// Create AES Cipher Instance
	cipher_block, err := aes.NewCipher(key_enc_bytes)
	if (err != nil) {
		fmt.Println("Error - aes.NewCipher - Key Error\n\n")
	}

	// Encryption
	if (len(plainText)<16) {
		rem := 16 - len(plainText)
		for i:=0; i<rem; i++ {
			plainText = append(plainText, byte(rem))
		}
		xor__iv_msg := XorBlocks(iv, plainText)
		cipherText := make([]byte, aes.BlockSize)	
		cipher_block.Encrypt(cipherText, xor__iv_msg)
		fmt.Println("\n\nCipher Text: ", string(cipherText))
	} else {
		block_count := len(plainText)/16
		
		/*
			Add padding based on the specifications to modify the (message)||(hmac_tag) as:
			[]cipherText <=> [message][hmac_tag][padding]
		*/
		
		plainText_mod16 := len(plainText) % 16
		
		/* DEBUG
		
		fmt.Println(
		"\n\t\t message: ", message,
		"\n\t\t len(message) <including +1 for the '\\n' at the end of the message> = ", len(message),
		"\n\t\t mac_tag: ", mac_tag,
		"\n\t\t len(mac_tag) = ", len(mac_tag),
		"\n\t\t len(plainText) = ", len(plainText),
		"\n\t\t n is ",plainText_mod16,
		"\n\t\t")
		
		*/
		
		if (plainText_mod16 == 0) {
			for i:=0; i<16; i++ {
				plainText = append(plainText, 0x10)
			}
		} else {
			remaining := 16 - plainText_mod16
			pad := byte(remaining)
			//fmt.Println("\n\t\t Pad:", byte(pad))
			for i:=0; i<remaining; i++ {
				plainText = append(plainText, pad)
			}
		}
		//fmt.Println("\n\t\t Padded plainText: ", plainText, "\nLen: ", len(plainText))

		/* Now the plainText is ready to be encrypted  */

		cipherText := make([]byte, AesBlockSize * (block_count + 1))
		xor_product := XorBlocks(iv, plainText[0:AesBlockSize])
		cipher_block.Encrypt(cipherText[0:AesBlockSize], xor_product)

		for i:=1; i<=block_count; i++ {
			xor_product = XorBlocks(cipherText[((i-1)*AesBlockSize):(i*AesBlockSize)], plainText[(AesBlockSize*i):((i+1)*AesBlockSize)])
			cipher_block.Encrypt(cipherText[(i*AesBlockSize):((i+1)*AesBlockSize)], xor_product)
		}
		
		//fmt.Println("\n\t\t CipherText: ", cipherText, "\nLen", len(cipherText))

		//Concatenate the IV to the cipherText
		iv__cipherText := make([]byte, len(iv) + len(cipherText))
		iv__cipherText = iv
		for i:=0; i<len(cipherText); i++ {
			iv__cipherText = append(iv__cipherText, cipherText[i])
		}
		//fmt.Println("\n\t\t Final Output:\n", iv__cipherText, "\nLen: ", len(iv__cipherText))
		
		// Write out the final file
		err := ioutil.WriteFile(outputFileName, iv__cipherText, 0644)
		if (err != nil) {
			fmt.Println("Error - Writing the output file: ", outputFileName)
		} else {
			fmt.Println("* File successfully encrypted: ", outputFileName, "\n")
		}
	}
		
}

func Decrypt(iv__cipherText []byte, key_enc_bytes []byte, key_hmac_bytes []byte, outputFileName string) {
	AesBlockSize := 16
	IvLength := 16
	
	// Extract the IV and the CipherText
	iv := iv__cipherText[0:IvLength]
	cipherText := make([]byte, len(iv__cipherText) - IvLength)
	cipherText = iv__cipherText[IvLength:len(iv__cipherText)]
	
	// CipherText length check
	if (len(cipherText) % AesBlockSize != 0) {
		fmt.Println("\nLength of cipherText is ", len(cipherText))
		fmt.Println("Error - Invalid CipherText - Not a multiple of ", AesBlockSize)
		showUsage()
		os.Exit(1)
	}
	
	// Create AES Cipher Instance
	cipher_block, err := aes.NewCipher(key_enc_bytes)
	if (err != nil) {
		fmt.Println("Error - aes.NewCipher - Key Error\n\n")
		showUsage()
		os.Exit(1)
	}

	// Decryption
	
	if (len(cipherText) == 16) {
		plainText := make([]byte, AesBlockSize)
		cipher_block.Decrypt(plainText[0:AesBlockSize],cipherText[0:AesBlockSize])
		//plainText[0:AesBlockSize] = XorBlocks(iv, plainText[0:AesBlockSize])
		plainText = XorBlocks(iv, plainText[0:AesBlockSize])
		
	} else if (len(cipherText) > 16) {
		block_count := len(cipherText)/AesBlockSize
		plainText := make([]byte, len(cipherText))
		
		// First Block
		cipher_block.Decrypt(plainText[0:AesBlockSize], cipherText[0:AesBlockSize])
		// XOR to get the first plainText block
		temp := XorBlocks(iv, plainText[0:AesBlockSize])
		copy(plainText[0:AesBlockSize], temp[:])
		
		// Remaining Blocks - Decrypt then XOR
		for i:=1; i<block_count; i++ {
			cipher_block.Decrypt(plainText[AesBlockSize*i : AesBlockSize*(i+1)], cipherText[AesBlockSize*i : AesBlockSize*(i+1)])
			// XOR to get the plainText block
			temp = XorBlocks(cipherText[AesBlockSize*(i-1) : AesBlockSize*i], plainText[AesBlockSize*i : AesBlockSize*(i+1)])
			copy(plainText[AesBlockSize*i : AesBlockSize*(i+1)], temp[:])
		}
		
		//fmt.Println("\n\n\t CipherText: ", cipherText, "\nDecrypted CipherText: ", plainText)
		
		/* 
			Now we have the decrypted the cipherText as plainText in the format:
			[]plainText <=> [message][hmac_tag][padding]
		*/
		
		// Check Padding based on the specifications
		paddingBlock := plainText[len(plainText) - 1]
		for i:=len(plainText)-1; i>=len(plainText)-int(paddingBlock); i-- {
			if (plainText[i] != paddingBlock) {
				fmt.Println("Error - Padding Invalid")
				showUsage()
				os.Exit(1)
			}
		}
		
		// Retrieve and verify the mac_tag
		message__mac_tag := make([]byte, len(plainText)-int(paddingBlock))
		message__mac_tag = plainText[:len(plainText)-int(paddingBlock)]
		mac_tag := make([]byte, 32)
		mac_tag = message__mac_tag[len(message__mac_tag)-32:]
		messageSize :=  len(plainText)-int(paddingBlock)-32
		message := make([]byte, messageSize)
		message = plainText[0:messageSize]
		message_tag := hmac_sha256(key_hmac_bytes, message)
		for i:=0; i<32; i++ {
			if(message_tag[i] != mac_tag[i]) {
				fmt.Println("Error - MAC Tags Mismatch - Can not veryfy message authenticity")
				showUsage()
			}
		}
		
		// Write out the final file
		err := ioutil.WriteFile(outputFileName, message, 0644)
		if (err != nil) {
			fmt.Println("Error - Writing the output file: ", outputFileName)
		} else {
			fmt.Println("* File successfully decrypted: ", outputFileName, "\n")
		}
	} 
}

//
/* -- MAIN -- */
//

func main() {
	if len(os.Args) < 7 {
		showUsage()
		os.Exit(1)
	}

	mode := os.Args[1]
	//key:="1234567890abcdef1234567890abcdef00001111000011110000111100001111"
	key := os.Args[3]
	inputFileName := os.Args[5]
	outputFileName:= os.Args[7]
	
	// Processing parameter - "key"
	if (len(key) != 64) {
		fmt.Println("Error - The key specified must be 64 characters in length and not ", len(key), "\n\n")
		showUsage()
		os.Exit(1)
	}
	key_enc := key[0:32]
	key_hmac := key[32:64]
	key_enc_bytes, _ := hex.DecodeString(key_enc)
	key_hmac_bytes, _ := hex.DecodeString(key_hmac) 
	
	// Processing parameter - "inputFileName"
	inputData, err := ioutil.ReadFile(inputFileName)
	if (err != nil) {
		fmt.Println("Error - Reading the input file: " + inputFileName + "\n\n")
		showUsage()
		os.Exit(1)
	}

	// Executing Selected Mode
	if mode == "encrypt" {
		fmt.Println("\n")
		// Generate the IV
		iv := make([]byte, 16)
		len_iv, err := rand.Read(iv)
		if (err != nil) {
			fmt.Println("Error - The IV can not be generated\n\n")
		}
		
		fmt.Println("Generated IV of length ", len_iv, "\n")
		
		// Encrypt-AES-CBC
		Encrypt(inputData, iv, key_enc_bytes, key_hmac_bytes, outputFileName)
	}
	if mode == "decrypt" {
		fmt.Println("\n")
		Decrypt(inputData, key_enc_bytes, key_hmac_bytes, outputFileName)
	}

	//fmt.Println("\n" + outputFileName +"\n" + key_enc + key_hmac)

}

