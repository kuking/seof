
all: clean build test coverage release

clean:
	go clean -testcache -testcache
	rm -f seof

build:
	go build ./...

test:
	go test ./...

coverage:
	go test -cover -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

release:
	go build -o seof cli/seof/main.go
