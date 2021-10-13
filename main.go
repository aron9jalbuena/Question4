package main

import (
	//Echo Packages
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	shell "github.com/ipfs/go-ipfs-api"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {

	type content struct {
		Text     string `json:"text"`
		Keyinput string `json:"keyinput"`
	}

	type decryptcontent struct {
		Cid      string `json:"cid"`
		Keyinput string `json:"keyinput"`
	}

	// Echo instance
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	e.GET("/", func(c echo.Context) error {
		fmt.Print("Enter webpage")
		return c.String(http.StatusOK, "Welcome")
	})

	//Get Function
	e.POST("/get", func(c echo.Context) error {

		decryptData := new(decryptcontent)

		if err := c.Bind(decryptData); err != nil {
			return err
		}

		key := []byte(decryptData.Keyinput)

		sh := shell.NewShell("localhost:5001")

		//Locate to current directory
		path, err2 := os.Getwd()
		if err2 != nil {
			return c.String(http.StatusBadRequest, "Working Directory Error")
		}

		//Check if we have gotten that file already
		if _, checkErr := os.Stat("cid"); os.IsNotExist(checkErr) {

			//If File Does Not Exist Cotinue
			//Get the file from ipfs
			getError := sh.Get(decryptData.Cid, path)
			if getError != nil {
				fmt.Printf("GetFile error: %s", getError)
			}

			//Store files data into a variable
			textData, readErr := ioutil.ReadFile(decryptData.Cid)
			if readErr != nil {
				fmt.Printf("read error: %s", readErr)
			}

			//Convert to string
			textString := string(textData[:])

			//Decrypt
			decryptText := decrypt(key, textString)

			return c.String(http.StatusOK, decryptText)

		}

		//If File is already in our directory
		return c.String(http.StatusFound, "Already Have File")

	})

	//Post Function
	e.POST("/add", func(c echo.Context) error {

		databinded := new(content)

		if err := c.Bind(databinded); err != nil {
			return err
		}

		//Make Sure key is off right size for encrypting
		if len(databinded.Keyinput) == 16 || len(databinded.Keyinput) == 24 || len(databinded.Keyinput) == 32 {

			key := []byte(databinded.Keyinput)

			//Encrypt Text
			encryptedText := encrypt(key, databinded.Text)

			//Write data to IPFS
			sh := shell.NewShell("localhost:5001")
			cid, err := sh.Add(strings.NewReader(encryptedText))
			if err != nil {
				fmt.Fprint(os.Stderr, "error: %s", err)
			}

			fmt.Println("\n" + encryptedText + "\n")
			return c.JSON(http.StatusOK, cid)

		}

		fmt.Println("key: " + databinded.Keyinput)
		return c.JSON(http.StatusBadRequest, "Didnt Work: ")
	})

	// Start server
	e.Logger.Fatal(e.Start(":1323"))

}

// encrypt string to base64 crypto using AES
func encrypt(key []byte, text string) string {
	// key := []byte(keyText)
	plaintext := []byte(text)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// convert to base64
	return base64.URLEncoding.EncodeToString(ciphertext)
}

// decrypt from base64 to decrypted string
func decrypt(key []byte, cryptoText string) string {
	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext)
}

/*
func postIPFS(c echo.Context) error {


	//Get Text and Key to Encrypt
	text := c.FormValue("name")
	keyinput := c.FormValue("key")
	if len(keyinput) != 16 || len(keyinput) != 24 || len(keyinput) != 32 {
		return c.String(http.StatusNotAcceptable, "Wrong Input Size For Key")
	}


		key := []byte(keyinput)

		//Encrypt Text
		encodedText := encrypt(key, text)

		//Start Shell and Upload encoded text to IPFS
		sh := shell.NewShell("localhost:5001")
		cid, err := sh.Add(strings.NewReader(encodedText))
		if err != nil {
			fmt.Fprint(os.Stderr, "error %s", err)
			os.Exit(1)
		}


	return c.String(http.StatusOK, "Input: "+text+", Key: "+keyinput)

}
*/
