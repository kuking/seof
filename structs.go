package seof

import (
	"errors"
	"github.com/kuking/seof/crypto"
)

const HeaderMagic uint64 = 0xb0a713

type Header struct {
	Magic         uint64
	ScriptSalt    [96]byte
	ScriptN       uint32
	ScriptR       uint32
	ScriptP       uint32
	DiskBlockSize uint32
	TailOfZeros   [8]byte
}

func (h *Header) Verify() error {
	if h.Magic != HeaderMagic {
		return errors.New("header: invalid magic")
	}
	if h.DiskBlockSize < 1500 || h.DiskBlockSize > 196608 {
		return errors.New("header: invalid disk_block_size")
	}
	for i := 0; i < len(h.ScriptSalt); i++ {
		if h.ScriptSalt[i] != 0 {
			break
		}
		if i == len(h.ScriptSalt)-1 {
			return errors.New("header: zero salt")
		}
	}

	if h.ScriptN > crypto.MaxSCryptParameters.N || h.ScriptN < crypto.MinSCryptParameters.N ||
		h.ScriptR > crypto.MaxSCryptParameters.R || h.ScriptR < crypto.MinSCryptParameters.R ||
		h.ScriptP > crypto.MaxSCryptParameters.P || h.ScriptP < crypto.MinSCryptParameters.P {
		return errors.New("header: invalid scrypt parameters")
	}

	for i := 0; i < len(h.TailOfZeros); i++ {
		if h.TailOfZeros[i] != 0 {
			return errors.New("header: tail of zeros not correct")
		}
	}

	return nil
}

type BlockEnvelop struct {
	Nounce     [96]byte
	CipherText []byte
}

type BlockZero struct {
	BEncFileSize  uint64 //BEnc as 'Before Encryption'
	BEncBlockSize uint32
	DiskBlockSize uint32
	BlocksWritten uint64
}
