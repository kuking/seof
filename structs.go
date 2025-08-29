package seof

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/kuking/seof/crypto"
)

const HeaderMagic uint64 = 0xb0a713c
const HeaderLength int = 128

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
	if h.DiskBlockSize < 1112 || h.DiskBlockSize > 196608 {
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
	Nonce         [nonceSize]byte
	CipherTextLen uint32
	CipherText    []byte
}

type BlockZero struct {
	BEncBlockSize uint32 //BEnc as 'Before Encryption'
	DiskBlockSize uint32
	BEncFileSize  uint64 //reported file size
	BlocksWritten uint64
}

func (z *BlockZero) Bytes() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, z)
	return buf.Bytes()
}

func BlockZeroFromBytes(b []byte) (*BlockZero, error) {
	r := bytes.NewReader(b)
	bz := BlockZero{}
	err := binary.Read(r, binary.LittleEndian, &bz)
	if err != nil {
		return nil, err
	}
	return &bz, nil
}
