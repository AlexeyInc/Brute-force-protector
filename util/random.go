package util

import (
	mathRand "math/rand"
	"strings"
	"time"
)

const (
	_ipLen       = 7
	_loginLen    = 5
	_passwordLen = 8
	_alphabet    = "abcdefghijklmnopqrstuvwxyz"
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
	return RandomString(_ipLen)
}

func RandomLogin() string {
	return RandomString(_loginLen)
}

func RandomPassword() string {
	return RandomString(_passwordLen)
}

func UpdateRandSeed() {
	mathRand.Seed(time.Now().UnixNano())
}
