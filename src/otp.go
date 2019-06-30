package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"hash"
	"math"
	"math/rand"
	"net/url"
	"strings"
	"time"
)

type OTP struct {
	secret string
	digits int
	hasher *Hasher
}

type TOTP struct {
	OTP
	interval int
}

type HOTP struct {
	OTP
}

type Hasher struct {
	HashName string
	Digest   func() hash.Hash
}

const (
	OtpTypeTotp = "totp"
	OtpTypeHotp = "hotp"
)

func NewOTP(secret string, digits int, hasher *Hasher) OTP {
	if hasher == nil {
		hasher = &Hasher{
			HashName: "sha1",
			Digest:   sha1.New,
		}
	}
	return OTP{
		secret: secret,
		digits: digits,
		hasher: hasher,
	}
}

func (o *OTP) generateOTP(input int) string {
	if input < 0 {
		panic("input must be positive integer")
	}
	hasher := hmac.New(o.hasher.Digest, o.byteSecret())
	hasher.Write(Itob(input))
	hmacHash := hasher.Sum(nil)
	offset := int(hmacHash[len(hmacHash)-1] & 0xf)
	code := ((int(hmacHash[offset]) & 0x7f) << 24) |
		((int(hmacHash[offset+1] & 0xff)) << 16) |
		((int(hmacHash[offset+2] & 0xff)) << 8) |
		(int(hmacHash[offset+3]) & 0xff)

	code = code % int(math.Pow10(o.digits))
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", o.digits), code)
}

func (o *OTP) byteSecret() []byte {
	missingPadding := len(o.secret) % 8
	if missingPadding != 0 {
		o.secret = o.secret + strings.Repeat("=", 8-missingPadding)
	}
	bytes, err := base32.StdEncoding.DecodeString(o.secret)
	if err != nil {
		panic("decode secret failed")
	}
	return bytes
}

func NewHOTP(secret string, digits int, hasher *Hasher) *HOTP {
	otp := NewOTP(secret, digits, hasher)
	return &HOTP{OTP: otp}

}

func NewDefaultHOTP(secret string) *HOTP {
	return NewHOTP(secret, 6, nil)
}

func (h *HOTP) At(count int) string {
	return h.generateOTP(count)
}

func (h *HOTP) Verify(otp string, count int) bool {
	return otp == h.At(count)
}

func (h *HOTP) ProvisioningUri(accountName, issuerName string, initialCount int) string {
	return BuildUri(
		OtpTypeHotp,
		h.secret,
		accountName,
		issuerName,
		h.hasher.HashName,
		initialCount,
		h.digits,
		0)
}

func NewTOTP(secret string, digits, interval int, hasher *Hasher) *TOTP {
	otp := NewOTP(secret, digits, hasher)
	return &TOTP{OTP: otp, interval: interval}
}

func NewDefaultTOTP(secret string) *TOTP {
	return NewTOTP(secret, 6, 30, nil)
}

func (t *TOTP) At(timestamp int) string {
	return t.generateOTP(t.timecode(timestamp))
}

func (t *TOTP) Verify(otp string, timestamp int) bool {
	return otp == t.At(timestamp)
}

func (t *TOTP) Now() string {
	return t.At(int(time.Now().Unix()))
}

func (t *TOTP) NowWithExpiration() (string, int64) {
	interval64 := int64(t.interval)
	timeCodeInt64 := time.Now().Unix() / interval64
	expirationTime := (timeCodeInt64 + 1) * interval64
	return t.generateOTP(int(timeCodeInt64)), expirationTime
}

func (t *TOTP) timecode(timestamp int) int {
	return int(timestamp / t.interval)
}

func (t *TOTP) ProvisioningUri(accountName, issuerName string) string {
	return BuildUri(
		OtpTypeTotp,
		t.secret,
		accountName,
		issuerName,
		t.hasher.HashName,
		0,
		t.digits,
		t.interval)
}

func BuildUri(otpType, secret, accountName, issuerName, algorithm string, initialCount, digits, period int) string {
	if otpType != OtpTypeHotp && otpType != OtpTypeTotp {
		panic("otp type error, got " + otpType)
	}
	urlParams := make([]string, 0)
	urlParams = append(urlParams, "secret="+secret)
	if otpType == OtpTypeHotp {
		urlParams = append(urlParams, fmt.Sprintf("counter=%d", initialCount))
	}
	label := url.QueryEscape(accountName)
	if issuerName != "" {
		issuerNameEscape := url.QueryEscape(issuerName)
		label = issuerNameEscape + ":" + label
		urlParams = append(urlParams, "issuer="+issuerNameEscape)
	}
	if algorithm != "" && algorithm != "sha1" {
		urlParams = append(urlParams, "algorithm="+strings.ToUpper(algorithm))
	}
	if digits != 0 && digits != 6 {
		urlParams = append(urlParams, fmt.Sprintf("digits=%d", digits))
	}
	if period != 0 && period != 30 {
		urlParams = append(urlParams, fmt.Sprintf("period=%d", period))
	}
	return fmt.Sprintf("otpauth://%s/%s?%s", otpType, label, strings.Join(urlParams, "&"))
}

func RandomSecret(length int) string {
	rand.Seed(time.Now().UnixNano())
	letterRunes := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
	bytes := make([]rune, length)
	for i := range bytes {
		bytes[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(bytes)
}

func Itob(integer int) []byte {
	byteArr := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		byteArr[i] = byte(integer & 0xff)
		integer = integer >> 8
	}
	return byteArr
}
