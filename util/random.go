package util

// TODO: change math/crypto...
import (
	"crypto/rand"
	"encoding/binary"
	"log"
	"math/big"
	mathrand "math/rand"
	"net"
	"strings"
)

const (
	_credsLen = 5
	_alphabet = "abcdefghijklmnopqrstuvwxyz"
)

func RandomInt(max int64) int {
	nBig, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		log.Fatal(err)
	}
	res := nBig.Int64()
	return int(res)
}

func RandomIntRange(min, max int64) int {
	nBig, err := rand.Int(rand.Reader, big.NewInt(max-min+1))
	if err != nil {
		log.Fatal(err)
	}
	return int(nBig.Int64() + min)
}

func RandomString(n int) string {
	var sb strings.Builder
	k := len(_alphabet)

	for i := 0; i < n; i++ {
		c := _alphabet[RandomInt(int64(k))]
		sb.WriteByte(c)
	}
	return sb.String()
}

func RandomIP() string {
	buf := make([]byte, 4)

	ip := mathrand.Uint32() //nolint

	binary.LittleEndian.PutUint32(buf, ip)

	return net.IP(buf).String()
}

func RandomLogin() string {
	return RandomString(_credsLen)
}

func RandomPassword() string {
	return RandomString(_credsLen)
}
