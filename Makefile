BINARY := pglrd
PKG    := ./...
BIN    := bin/$(BINARY)

.PHONY: all
all: fmt-check vet test build

.PHONY: build
build:
	go build -o bin/ ./cmd/...

.PHONY: run
run:
	go run ./cmd/pglrd

.PHONY: test
test:
	go test -race $(PKG)

.PHONY: migrate
migrate:
	go run ./cmd/pglr-migrate up

.PHONY: migrate-down
migrate-down:
	go run ./cmd/pglr-migrate down

.PHONY: migrate-status
migrate-status:
	go run ./cmd/pglr-migrate status

.PHONY: cover
cover:
	go test -race -coverprofile=coverage.out $(PKG)
	go tool cover -func=coverage.out

.PHONY: vet
vet:
	go vet $(PKG)

.PHONY: fmt
fmt:
	gofmt -s -w .

.PHONY: fmt-check
fmt-check:
	@out="$$(gofmt -s -l .)"; \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

.PHONY: lint
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed; running go vet instead"; go vet $(PKG); \
	fi

.PHONY: up
up:
	docker compose up -d

.PHONY: down
down:
	docker compose down -v

.PHONY: clean
clean:
	rm -rf bin coverage.out coverage.html
