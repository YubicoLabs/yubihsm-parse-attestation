.PHONY: build
build:
	go build -ldflags "-w -s" -o build/yubihsm-parse-attestation .
