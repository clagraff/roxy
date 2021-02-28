.PHONY: build
build:
	go build -o bin/roxy-dev main.go

	CGO_ENABLED=0 GOOS=freebsd GOARCH=386 go build -o bin/roxy-freebsd-386 main.go
	CGO_ENABLED=0 GOOS=linux GOARCH=386 go build -o bin/roxy-linux-386 main.go
	CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -o bin/roxy-windows-386 main.go
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -o bin/roxy-freebsd-amd64 main.go
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o bin/roxy-darwin-amd64 main.go
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/roxy-linux-amd64 main.go
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/roxy-windows-amd64 main.go

.PHONY: run
run:
	go run -race main.go

.PHONY: clean
clean:
	go clean