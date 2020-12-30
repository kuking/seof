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

const nonceSize int = 36

type File struct {
	file       *os.File
	pendingErr *error
	blockZero  BlockZero
	aead       [3]cipher.AEAD
	cache      *lru.Cache
	cursor     uint64
}

type inMemoryBlock struct {
	modified  bool
	plainText []byte
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
	blockNo := blockI.(uint64)
	imb := dataI.(*inMemoryBlock)
	if !imb.modified {
		return
	}

	blockOffset := int64(HeaderLength) + int64(f.blockZero.DiskBlockSize)*int64(blockNo)
	newOfs, err := f.file.Seek(blockOffset, 0)
	if newOfs != blockOffset {
		err := errors.New("failed to fseek")
		f.pendingErr = &err
		return
	}
	if err != nil {
		f.pendingErr = &err
		return
	}

	cipherText, nonce := f.seal(imb.plainText, blockNo)
	n, err := f.file.Write(nonce)
	if err != nil {
		f.pendingErr = &err
		return
	}
	if n != len(nonce) {
		err := errors.New("could not write fully to disk")
		f.pendingErr = &err
		return
	}
	err = binary.Write(f.file, binary.LittleEndian, uint32(len(cipherText)))
	if err != nil {
		f.pendingErr = &err
		return
	}
	n, err = f.file.Write(cipherText)
	if n != len(cipherText) {
		err := errors.New("could not write fully to disk")
		f.pendingErr = &err
		return
	}
	if err != nil {
		f.pendingErr = &err
		return
	}
	f.blockZero.BlocksWritten++
}

func (f *File) getOrLoadBlock(blockNo uint64) (*inMemoryBlock, error) {

	if imb, ok := f.cache.Get(blockNo); ok {
		return imb.(*inMemoryBlock), nil
	}

	blockOffset := int64(HeaderLength) + int64(f.blockZero.DiskBlockSize)*int64(blockNo)
	f.file.Seek(blockOffset, 0)

	nonce := make([]byte, nonceSize)
	n, err := f.file.Read(nonce)
	if n != nonceSize {
		return nil, errors.New("could not read nonce bytes")
	}
	if err != nil {
		return nil, err
	}
	var cipherTextLen uint32
	err = binary.Read(f.file, binary.LittleEndian, &cipherTextLen)
	if err != nil {
		return nil, err
	}

	cipherText := make([]byte, cipherTextLen)
	n, err = f.file.Read(cipherText)
	if n != int(cipherTextLen) {
		return nil, errors.New("could not read cipherText from file")
	}
	if err != nil {
		return nil, err
	}

	plainText, err := f.open(cipherText, blockNo, nonce)
	if err != nil {
		return nil, err
	}
	imb := inMemoryBlock{
		modified:  false,
		plainText: plainText,
	}

	f.cache.Add(blockNo, &imb)

	return &imb, nil
}

func (f *File) seal(plainText []byte, blockNo uint64) (cipherText []byte, nonce []byte) {
	additional := make([]byte, 8)
	binary.LittleEndian.PutUint64(additional, blockNo)
	nonce = crypto.RandBytes(nonceSize)
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

	file.initialiseCache(memoryBuffers)

	file.blockZero = BlockZero{
		BEncBlockSize: 0,
		DiskBlockSize: header.DiskBlockSize, // only used for block 0
		BEncFileSize:  0,
		BlocksWritten: 0,
	}
	imb, err := file.getOrLoadBlock(0) //FIXME: blockZero should not be cached
	if err != nil {
		return nil, err
	}
	bz, err := BlockZeroFromBytes(imb.plainText)
	if err != nil {
		return nil, err
	}
	file.blockZero = *bz

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

	// header
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
	header.DiskBlockSize = 2000 // temporarily fixed for initialising ciphers

	err = file.initialiseCiphers(password, &header)
	if err != nil {
		return nil, err
	}

	file.initialiseCache(memoryBuffers)

	// calculates encrypted block size
	plainTextBlock := crypto.RandBytes(BEBlockSize)
	cipherText, _ := file.seal(plainTextBlock, 1)
	header.DiskBlockSize = uint32(nonceSize + 4 + len(cipherText)) // 4=length of uint32 for cipherTextLength

	// blockZero
	file.blockZero = BlockZero{
		BEncBlockSize: uint32(BEBlockSize),
		DiskBlockSize: header.DiskBlockSize,
		BEncFileSize:  0,
		BlocksWritten: 1,
	}

	// writes common headers
	file.file, err = os.Create(name)
	if err != nil {
		return nil, err
	}
	err = binary.Write(file.file, binary.LittleEndian, &header)
	if err != nil { // possible left open file
		return nil, err
	}

	imb := inMemoryBlock{
		modified:  true,
		plainText: file.blockZero.Bytes(),
	}
	file.flushBlock(uint64(0), &imb)

	return &file, nil
}

func (f *File) blockNoForCursor() uint64 {
	block := f.cursor / uint64(f.blockZero.BEncBlockSize)
	return block + 1 // because block zero is special, so everything is offset +1
}

func (f *File) Write(b []byte) (n int, err error) {
	if f.pendingErr != nil {
		return 0, *f.pendingErr
	}
	if len(b) == 0 {
		return 0, nil
	}
	blockNo := f.blockNoForCursor()
	imb, err := f.getOrLoadBlock(blockNo)
	if err != nil && f.cursor >= f.blockZero.BEncFileSize {
		// at the tail of the file, a new block is created
		newImb := inMemoryBlock{
			modified:  false,
			plainText: make([]byte, 0, f.blockZero.BEncBlockSize),
		}
		imb = &newImb
		f.cache.Add(blockNo, imb)
	}

	imb.modified = true
	// appends zeroes if not in the block
	ofsStart := int(f.cursor % uint64(f.blockZero.BEncBlockSize))
	if len(imb.plainText) < ofsStart {
		for i := len(imb.plainText); i < ofsStart; i++ {
			imb.plainText = append(imb.plainText, 0)
		}
	}
	// then fully write or partial
	if len(b) < ofsStart+int(f.blockZero.BEncBlockSize) {
		for i := len(imb.plainText); i < ofsStart+len(b); i++ {
			imb.plainText = append(imb.plainText, 0)
		}
		copy(imb.plainText[ofsStart:], b)
		f.cursor += uint64(len(b))
		return len(b), nil
	} else {
		partial := int(f.blockZero.BEncBlockSize) - ofsStart
		imb.plainText = append(imb.plainText[0:ofsStart], b[0:partial]...)
		f.cursor += uint64(partial)
		n, err := f.Write(b[partial:])
		return partial + n, err
	}
}

func (f *File) Read(b []byte) (n int, err error) {
	if f.pendingErr != nil {
		return 0, *f.pendingErr
	}
	blockNo := f.blockNoForCursor()
	imb, err := f.getOrLoadBlock(blockNo)
	if err != nil {
		return 0, err
	}
	ofsStart := int(f.cursor % uint64(f.blockZero.BEncBlockSize))

	if len(imb.plainText) != int(f.blockZero.BEncBlockSize) {
		// at end of file, we read what we can --- or end of block-ish //XXX: potential bug here
		copy(b[:], imb.plainText[ofsStart:])
		n := len(imb.plainText) - ofsStart
		f.cursor += uint64(n)
		return n, nil
	}

	if len(b) < len(imb.plainText)-ofsStart {
		// smaller chunk
		copy(b[:], imb.plainText[ofsStart:])
		f.cursor += uint64(len(b))
		return len(b), nil
	}

	// bigger chunk
	partial := int(f.blockZero.BEncBlockSize) - ofsStart
	copy(b[:], imb.plainText[ofsStart:])
	f.cursor += uint64(partial)
	n, err = f.Read(b[partial:])
	return n + partial, err
}

func (f *File) Close() error {
	f.cache.Purge()
	f.flushBlock(uint64(0), &inMemoryBlock{
		modified:  true,
		plainText: f.blockZero.Bytes(),
	})
	return f.file.Close()
}
