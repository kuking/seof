package seof

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"github.com/kuking/seof/crypto"
	"golang.org/x/crypto/scrypt"
	"os"
)

type File struct {
	file          *os.File
	diskBlockSize uint32
	aead          [3]cipher.AEAD
}

func (f *File) initialiseCiphers(password string, header *Header) error {
	err := header.Verify()
	if err != nil {
		return err
	}
	var key []byte
	key, err = scrypt.Key([]byte(password), header.ScriptSalt[:], int(header.ScriptN), int(header.ScriptR), int(header.ScriptP), 96)
	if err != nil {
		return err
	}
	var block cipher.Block
	keySize := 32
	for i := 0; i < 3; i++ {
		block, err = aes.NewCipher(key[keySize*i : keySize*(i+1)])
		if err != nil {
			return err
		}
		f.aead[i], err = cipher.NewGCM(block)
		if err != nil {
			return err
		}
	}
	return nil
}

func Create(name string) (*File, error) {
	return nil, errors.New("use CreateExt")
}

func Open(name string) (*File, error) {
	return nil, errors.New("use OpenExt")
}

func OpenFile(name string, flag int, perm os.FileMode) (*File, error) {
	return nil, errors.New("use OpenExt")
}

func OpenExt(name string, password string, memoryBuffers int) (*File, error) {
	if memoryBuffers < 1 || memoryBuffers > 128 {
		return nil, errors.New("memory buffers can be between 1 and 128")
	}

	var err error
	file := File{}
	header := Header{}
	file.file, err = os.Open(name)
	if err != nil {
		return nil, err
	}
	err = binary.Read(file.file, binary.LittleEndian, &header)
	if err != nil {
		return nil, err
	}
	err = file.initialiseCiphers(password, &header)
	if err != nil {
		return nil, err
	}

	return &file, nil
}

func CreateExt(name string, password string, BEBlockSize int, memoryBuffers int) (*File, error) {
	if len(password) < 20 {
		return nil, errors.New("password should be at least 20 characters long")
	}
	if BEBlockSize < 1024 || BEBlockSize > 128*1024 {
		return nil, errors.New("before encryption block size has to be between 1KB and 128KB")
	}
	if memoryBuffers < 1 || memoryBuffers > 128 {
		return nil, errors.New("memory buffers can be between 1 and 128")
	}

	var err error
	file := File{}

	header := Header{
		Magic:         HeaderMagic,
		ScriptSalt:    [96]byte{},
		ScriptN:       crypto.CurrentSCryptParameters.N,
		ScriptR:       crypto.CurrentSCryptParameters.R,
		ScriptP:       crypto.CurrentSCryptParameters.P,
		DiskBlockSize: 0,
		TailOfZeros:   [8]byte{},
	}
	copy(header.ScriptSalt[:], crypto.RandBytes(len(header.ScriptSalt)))
	header.DiskBlockSize = 2000 // fixed

	err = file.initialiseCiphers(password, &header)
	if err != nil {
		return nil, err
	}
	// FIXME: set correct header.DiskBlockSize

	file.file, err = os.Create(name)
	if err != nil {
		return nil, err
	}
	err = binary.Write(file.file, binary.LittleEndian, &header)
	if err != nil { // possible left open file
		return nil, err
	}
	// pending block 0

	return &file, nil
}

func (f *File) Write(b []byte) (n int, err error) {
	return f.file.Write(b)
	//return 0, errors.New("not implemented")
}

func (f *File) Read(b []byte) (n int, err error) {
	return f.file.Read(b)
	//return 0, errors.New("not implemented")
}

func (f *File) Close() error {
	return f.file.Close()
	//return errors.New("not implemented")
}
