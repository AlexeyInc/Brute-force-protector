package util

// TODO: change math/crypto
import (
	mathRand "math/rand"
	"strings"
	"time"
)

const (
	_credsLen = 5
	_alphabet = "abcdefghijklmnopqrstuvwxyz"
)

func RandomInt(max int) int {
	UpdateRandSeed()
	return mathRand.Intn(max)
}

func RandomIntRange(min, max int) int {
	UpdateRandSeed()
	return (mathRand.Intn(max-min+1) + min)
}

func RandomString(n int) string {
	var sb strings.Builder
	k := len(_alphabet)

	for i := 0; i < n; i++ {
		c := _alphabet[RandomInt(k)]
		sb.WriteByte(c)
	}
	return sb.String()
}

func RandomIP() string {
	return RandomString(_credsLen)
}

func RandomLogin() string {
	return RandomString(_credsLen)
}

func RandomPassword() string {
	return RandomString(_credsLen)
}

func UpdateRandSeed() {
	mathRand.Seed(time.Now().UnixNano())
}
