package assets

import (
	_ "embed"
)

//go:embed whitelistSubnets.txt
var whiteIPs []byte

//go:embed blacklistSubnets.txt
var blackIPs []byte

func ReadWhiteList() []byte {
	return whiteIPs
}

func ReadBlackList() []byte {
	return blackIPs
}
