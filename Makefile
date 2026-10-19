.PHONY: build test vet run clean

BINARY := passkit

build:
	CGO_ENABLED=0 go build -o $(BINARY) ./cmd/passkit

test:
	go test -v ./...

vet:
	go vet ./...

run:
	go run ./cmd/passkit

clean:
	rm -f $(BINARY)
