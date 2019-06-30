package main

import (
	"fmt"
	"io/ioutil"
	"time"

	otp "github.com/OzqurYalcin/otp/src"
	qr "rsc.io/qr"
)

func main() {
	secret := otp.RandomSecret(16)
	fmt.Println("secret key:", secret)
	totp := otp.NewDefaultTOTP(secret)
	url := totp.ProvisioningUri("account", "title")
	qrcode, err := qr.Encode(url, qr.Q)
	if err != nil {
		panic(err)
	}
	img := qrcode.PNG()
	err = ioutil.WriteFile("qr.png", img, 0600)
	if err != nil {
		panic(err)
	}
loop:
	for {
		var token string
		fmt.Printf("enter the token (or q to quit):")
		fmt.Scanln(&token)
		switch token {
		case "q":
			break loop
		default:
			val := totp.Verify(token, int(time.Now().Unix()))
			if !val {
				fmt.Println("Not Authenticated")
				continue
			}
			fmt.Println("Authenticated!")
		}
	}
}
