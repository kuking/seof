package seof

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	lru "github.com/hashicorp/golang-lru"
	"github.com/kuking/seof/crypto"
	"golang.org/x/crypto/scrypt"
	"io"
	"os"
	"sync"
	"time"
)

const nonceSize int = 36

type File struct {
	mutex      sync.Mutex
	file       *os.File
	pendingErr *error
	header     Header
	blockZero  BlockZero
	aead       [3]cipher.AEAD
	cache      *lru.Cache
	cursor     int64
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
	blockNo := blockI.(int64)
	imb := dataI.(*inMemoryBlock)
	if !imb.modified {
		return
	}

	blockOffset := int64(HeaderLength) + int64(f.blockZero.DiskBlockSize)*blockNo
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

	if len(imb.plainText) > int(f.blockZero.BEncBlockSize) {
		panic(fmt.Sprintf("block %v plainText too big: %v > %v\n", blockNo, len(imb.plainText), int(f.blockZero.BEncBlockSize)))
	}

	cipherText, nonce := f.seal(imb.plainText, uint64(blockNo))
	if len(cipherText) > int(f.blockZero.DiskBlockSize) {
		panic(fmt.Sprintf("cipherText encoded size too big: %v > %v\n", len(cipherText), f.blockZero.DiskBlockSize))
	}
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

func (f *File) flushBlockZero() {
	f.flushBlock(int64(0), &inMemoryBlock{
		modified:  true,
		plainText: f.blockZero.Bytes(),
	})
}

func (f *File) getOrLoadBlock(blockNo int64) (*inMemoryBlock, error) {

	if imb, ok := f.cache.Get(blockNo); ok {
		return imb.(*inMemoryBlock), nil
	}

	blockOffset := int64(HeaderLength) + int64(f.blockZero.DiskBlockSize)*blockNo
	seekOfs, err := f.file.Seek(blockOffset, 0)
	if err != nil {
		return nil, err
	}
	if seekOfs != blockOffset {
		return nil, errors.New("could not seek to block start")
	}

	nonce := make([]byte, nonceSize)
	n, err := f.file.Read(nonce)
	if err == io.EOF { // to help detection of EOF (so new blocks can be created.)
		return nil, err
	}
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

	plainText, err := f.unseal(cipherText, uint64(blockNo), nonce)
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

func (f *File) unseal(cipherText []byte, blockNo uint64, nonce []byte) (plainText []byte, err error) {
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

func Create(_ string) (*File, error) {
	return nil, errors.New("use CreateExt")
}

func Open(_ string) (*File, error) {
	return nil, errors.New("use OpenExt")
}

func OpenFile(_ string, _ int, _ os.FileMode) (*File, error) {
	return nil, errors.New("use OpenExt")
}

func OpenExt(name string, password string, memoryBuffers int) (*File, error) {
	if memoryBuffers < 1 || memoryBuffers > 1024 {
		return nil, errors.New("memory buffers can be between 1 and 1024")
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
	file.header = header

	err = file.initialiseCiphers(password, &header)
	if err != nil {
		return nil, err
	}

	err = file.initialiseCache(memoryBuffers)
	if err != nil {
		return nil, err
	}

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

func CreateExt(name string, password string, scryptParams crypto.SCryptParameters, BEBlockSize int, memoryBuffers int) (*File, error) {
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
		ScriptN:       scryptParams.N,
		ScriptR:       scryptParams.R,
		ScriptP:       scryptParams.P,
		DiskBlockSize: 0,
		TailOfZeros:   [8]byte{},
	}
	copy(header.ScriptSalt[:], crypto.RandBytes(len(header.ScriptSalt)))
	header.DiskBlockSize = 2000 // temporarily fixed for initialising ciphers

	err = file.initialiseCiphers(password, &header)
	if err != nil {
		return nil, err
	}

	err = file.initialiseCache(memoryBuffers)
	if err != nil {
		return nil, err
	}

	// calculates encrypted block size
	plainTextBlock := crypto.RandBytes(BEBlockSize)
	cipherText, _ := file.seal(plainTextBlock, 1)
	header.DiskBlockSize = uint32(nonceSize + 4 + len(cipherText)) // 4=length of uint32 for cipherTextLength
	file.header = header

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
	file.flushBlock(int64(0), &imb)

	return &file, nil
}

func (f *File) blockNoForOffset(offset int64) int64 {
	block := offset / int64(f.blockZero.BEncBlockSize)
	return block + 1 // because block zero is special, so everything is offset +1
}
func (f *File) blockNoForCursor() int64 {
	return f.blockNoForOffset(f.cursor)
}

func (f *File) Write(b []byte) (n int, err error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.writeLocked(b)
}

func (f *File) writeLocked(b []byte) (n int, err error) {
	if f.pendingErr != nil {
		return 0, *f.pendingErr
	}
	if len(b) == 0 {
		return 0, nil
	}
	blockNo := f.blockNoForCursor()
	var imb *inMemoryBlock
	imb, err = f.getOrLoadBlock(blockNo)

	if err != nil && err == io.EOF {
		// at the tail of the file, a new block is created
		newImb := inMemoryBlock{
			modified:  false,
			plainText: make([]byte, 0, f.blockZero.BEncBlockSize),
		}
		imb = &newImb
		f.cache.Add(blockNo, imb)
	} else if err != nil {
		return 0, err
	}

	imb.modified = true
	// appends zeroes if not intend to write at the beginning of the block, and the block is empty
	ofsStart := int(f.cursor % int64(f.blockZero.BEncBlockSize))
	for i := len(imb.plainText); i < ofsStart; i++ {
		imb.plainText = append(imb.plainText, 0)
	}

	availableInBlock := int(f.blockZero.BEncBlockSize) - ofsStart
	if len(b) < availableInBlock {
		// b fits wholly in this block
		// appends bytes to an potentially half-allocated block
		for i := len(imb.plainText); i < ofsStart+len(b); i++ {
			imb.plainText = append(imb.plainText, 0)
		}
		copy(imb.plainText[ofsStart:], b)
		f.cursor += int64(len(b))
		if uint64(f.cursor) > f.blockZero.BEncFileSize {
			f.blockZero.BEncFileSize = uint64(f.cursor)
		}
		return len(b), nil
	} else {
		// B won't fit wholly in this block
		imb.plainText = append(imb.plainText[0:ofsStart], b[0:availableInBlock]...)
		f.cursor += int64(availableInBlock)
		if uint64(f.cursor) > f.blockZero.BEncFileSize {
			f.blockZero.BEncFileSize = uint64(f.cursor)
		}
		n, err := f.writeLocked(b[availableInBlock:])
		return availableInBlock + n, err
	}
}

func (f *File) WriteAt(b []byte, off int64) (n int, err error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if off < 0 { //XXX: can this be relative?
		return 0, errors.New("negative offset not allowed")
	}
	f.cursor = off
	return f.writeLocked(b)
}

func (f *File) WriteString(s string) (n int, err error) {
	return f.Write([]byte(s))
}

func (f *File) Read(b []byte) (n int, err error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.readLocked(b)
}

func (f *File) readLocked(b []byte) (n int, err error) {
	if f.pendingErr != nil {
		return 0, *f.pendingErr
	}
	if len(b) == 0 {
		return 0, nil
	}
	if f.cursor >= int64(f.blockZero.BEncFileSize) {
		return 0, io.EOF
	}
	blockNo := f.blockNoForCursor()
	imb, err := f.getOrLoadBlock(blockNo)
	if err != nil {
		return 0, err
	}
	ofsStart := int(f.cursor % int64(f.blockZero.BEncBlockSize))

	if len(imb.plainText) != int(f.blockZero.BEncBlockSize) {
		// at end of file, we read what we can --- or end of block-ish //XXX: potential bug here
		copy(b[:], imb.plainText[ofsStart:])
		if len(b) < len(imb.plainText[ofsStart:]) {
			n = len(b)
		} else {
			n = len(imb.plainText[ofsStart:])
		}
		f.cursor += int64(n)
		return n, nil
	}

	if len(b) < len(imb.plainText)-ofsStart {
		// smaller chunk
		copy(b[:], imb.plainText[ofsStart:])
		f.cursor += int64(len(b))
		return len(b), nil
	}

	// bigger chunk
	partial := int(f.blockZero.BEncBlockSize) - ofsStart
	copy(b[:], imb.plainText[ofsStart:])
	f.cursor += int64(partial)
	if f.cursor == int64(f.blockZero.BEncFileSize) {
		// don't recurse, we know we are at the end of the file it will trigger an EOF as trying to read at EOF
		return partial, err
	}
	n, err = f.readLocked(b[partial:])
	return n + partial, err
}

func (f *File) ReadAt(b []byte, off int64) (n int, err error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if off < 0 { //XXX: can this be relative?
		return 0, errors.New("negative offset not allowed")
	}
	f.cursor = off
	return f.readLocked(b)
}

//func (f *File) ReadFrom(r io.Reader) (n int64, err error) {
//	panic("i dunno")
//}

func (f *File) Seek(offset int64, whence int) (ret int64, err error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if f.pendingErr != nil {
		return 0, *f.pendingErr
	}
	newCursor := int64(0)
	if whence == 0 {
		if offset < 0 { //XXX: can this be relative?
			return 0, errors.New("negative offset not allowed")
		}
		newCursor = offset
	} else if whence == 1 {
		newCursor = f.cursor + offset
	} else if whence == 2 {
		newCursor = int64(f.blockZero.BEncFileSize) - offset
	} else {
		return 0, errors.New("invalid whence value")
	}
	if newCursor < 0 {
		return 0, errors.New("absolute negative offset position not allowed")
	}
	if newCursor > int64(f.blockZero.BEncFileSize) {
		newCursor = int64(f.blockZero.BEncFileSize)
	}
	f.cursor = newCursor
	return f.cursor, nil
}

func (f *File) Sync() error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	for _, blockNoI := range f.cache.Keys() {
		imbI, ok := f.cache.Get(blockNoI)
		if ok {
			f.flushBlock(blockNoI, imbI)
		}
	}
	f.flushBlockZero()
	return f.file.Sync()
}

func (f *File) Truncate(size int64) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if f.pendingErr != nil {
		return *f.pendingErr
	}
	if size < 0 || uint64(size) > f.blockZero.BEncFileSize {
		return os.ErrInvalid
	}

	blockNo := f.blockNoForOffset(size)

	partial := size%int64(f.blockZero.BEncBlockSize) != 0
	if partial {
		imb, err := f.getOrLoadBlock(blockNo)
		if err != nil {
			return err
		}
		imb.plainText = imb.plainText[0 : size%int64(f.blockZero.BEncBlockSize)]
		imb.modified = true
	}

	if partial {
		blockNo++
	}
	for _, k := range f.cache.Keys() {
		cacheBlockNo := k.(int64)
		if blockNo <= cacheBlockNo {
			f.cache.Remove(k)
		}
	}

	f.blockZero.BEncFileSize = uint64(size)
	return f.file.Truncate(int64(HeaderLength) + int64(f.blockZero.DiskBlockSize)*blockNo)
}

func (f *File) Stat() (*SeofFileInfo, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	stats, err := f.file.Stat()
	if err != nil {
		return nil, err
	}

	return &SeofFileInfo{
		name:          f.Name(),
		size:          int64(f.blockZero.BEncFileSize),
		eSize:         stats.Size(),
		mode:          stats.Mode(),
		time:          stats.ModTime(),
		sys:           stats.Sys(),
		diskBlockSize: f.blockZero.DiskBlockSize,
		bEncBlockSize: f.blockZero.BEncBlockSize,
		blocksWritten: f.blockZero.BlocksWritten,
		scryptSalt:    f.header.ScriptSalt[:],
		scryptN:       f.header.ScriptN,
		scryptR:       f.header.ScriptR,
		scryptP:       f.header.ScriptP,
	}, nil
}

type SeofFileInfo struct {
	name          string
	size          int64
	eSize         int64
	mode          os.FileMode
	time          time.Time
	sys           interface{}
	diskBlockSize uint32
	bEncBlockSize uint32
	blocksWritten uint64
	scryptSalt    []byte
	scryptN       uint32
	scryptR       uint32
	scryptP       uint32
}

func (s SeofFileInfo) Name() string {
	return s.name
}
func (s SeofFileInfo) Size() int64 {
	return s.size
}
func (s SeofFileInfo) EncryptedSize() int64 {
	return s.eSize
}
func (s SeofFileInfo) Mode() os.FileMode {
	return s.mode
}
func (s SeofFileInfo) ModTime() time.Time {
	return s.time
}
func (_ SeofFileInfo) IsDir() bool {
	return false
}
func (s SeofFileInfo) Sys() interface{} {
	return s.sys
}
func (s SeofFileInfo) DiskBlockSize() uint32 {
	return s.diskBlockSize
}
func (s SeofFileInfo) BEBlockSize() uint32 {
	return s.bEncBlockSize
}
func (s SeofFileInfo) BlocksWritten() uint64 {
	return s.blocksWritten
}
func (s SeofFileInfo) SCryptParameters() (salt []byte, N, R, P uint32) {
	return s.scryptSalt, s.scryptN, s.scryptR, s.scryptP
}

func (f *File) Close() error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if f.pendingErr != nil && f.pendingErr != &os.ErrClosed {
		return *f.pendingErr
	}
	f.cache.Purge()
	f.flushBlockZero()
	closedErr := os.ErrClosed
	f.pendingErr = &closedErr
	return f.file.Close()
}

func (f *File) Name() string {
	return f.file.Name()
}
