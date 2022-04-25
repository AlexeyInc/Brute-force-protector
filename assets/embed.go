package assets

import (
	_ "embed"
)

//go:embed whitelist_IPs.txt
var whiteIPs []byte

//go:embed blacklist_IPs.txt
var blackIPs []byte

func ReadWhiteList() []byte {
	return whiteIPs
}

func ReadBlackList() []byte {
	return blackIPs
}
