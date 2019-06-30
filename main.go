package main

import (
	"fmt"
	"io/ioutil"
	"time"

	otp "otp/src"

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
		var code string
		fmt.Printf("enter the code (or q to quit):")
		fmt.Scanln(&code)
		switch code {
		case "q":
			break loop
		default:
			val := totp.Verify(code, int(time.Now().Unix()))
			if !val {
				fmt.Println("Not Authenticated")
				continue
			}
			fmt.Println("Authenticated!")
		}
	}
}
