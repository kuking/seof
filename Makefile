
all: clean build test coverage release

clean:
	go clean -testcache -testcache

build:
	go build ./...

test:
	go test ./...

coverage:
	go test -cover -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

release:
	true
