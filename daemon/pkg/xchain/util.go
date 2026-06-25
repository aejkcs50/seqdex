package xchain

import "encoding/hex"

func toHex(b []byte) string { return hex.EncodeToString(b) }

func fromHex(s string) ([]byte, error) { return hex.DecodeString(s) }
