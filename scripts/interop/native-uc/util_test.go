package nativeuc

import "crypto/sha256"

func sha256sum(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }
