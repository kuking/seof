package seof

import "errors"

type File struct {
}

func Create(name string) (*File, error) {
	return nil, errors.New("use CreateExt")
}

func CreateExt(name string, password string, blockSize int, memoryBuffers int) (*File, error) {
	return nil, errors.New("not implemented")
}
