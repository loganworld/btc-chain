package launcher

import (
	"github.com/ethereum/go-ethereum/params"
)

var (
	Bootnodes = []string{
		"enode://eddf49492ae9cec649f3c1783a1bfe40c0ba05cd487f6b3e47f0cb9100bda14cd4ba3c63d1db6265b0e78cef132463aa447f950590b205791f62b218ea6c569f@160.238.36.156:15060",
		"enode://580d8cc57ead46d0480003bd0f2d7ecc906de8e6c615a7db55c5c8dbdfe482a03a39b82342f0a69b73c108ecbddfa25eaa096d7eceb1a44c34d5c4f6b6fb03ac@31.220.57.80:15060",
		"enode://b24b61814867fb22d69d6245e89074da2d7adf0b2b1305ab187ea5e43d44e090c073d15eb5238d4d8342283cd2d0ebe01586d7479cfaf841dec4da3e4b8aced5@31.220.55.122:15060",
	}
)

func overrideParams() {
	params.MainnetBootnodes = []string{}
	params.RopstenBootnodes = []string{}
	params.RinkebyBootnodes = []string{}
	params.GoerliBootnodes = []string{}
}
