package seof

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	lru "github.com/hashicorp/golang-lru"
	"github.com/kuking/seof/crypto"
	"golang.org/x/crypto/scrypt"
	"os"
)

type File struct {
	file      *os.File
	blockZero BlockZero
	aead      [3]cipher.AEAD
	cache     *lru.Cache
	cursor    uint64
}

type intBlock struct {
	plaintext []byte
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

func (f *File) initialiseCache(size int) error {
	var err error
	f.cache, err = lru.NewWithEvict(size, f.flushBlock)
	return err
}

func (f *File) flushBlock(blockI interface{}, dataI interface{}) {
	//block := blockI.(uint64)
	//data := dataI.([]byte)

}

func (f *File) seal(plainText []byte, blockNo uint64) (cipherText []byte, nonce []byte) {
	additional := make([]byte, 8)
	binary.LittleEndian.PutUint64(additional, blockNo)
	nonce = crypto.RandBytes(36)
	cipherText = f.aead[0].Seal(nil, nonce[0:12], plainText, additional)
	cipherText = f.aead[1].Seal(nil, nonce[12:24], cipherText, additional)
	cipherText = f.aead[2].Seal(nil, nonce[24:36], cipherText, additional)
	return
}

func (f *File) open(cipherText []byte, blockNo uint64, nonce []byte) (plainText []byte, err error) {
	additional := make([]byte, 8)
	binary.LittleEndian.PutUint64(additional, blockNo)
	// 3
	cipherText, err = f.aead[2].Open(nil, nonce[24:36], cipherText, additional)
	if err != nil {
		return
	}
	cipherText, err = f.aead[1].Open(nil, nonce[12:24], cipherText, additional)
	if err != nil {
		return
	}
	plainText, err = f.aead[0].Open(nil, nonce[0:12], cipherText, additional)
	return
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
