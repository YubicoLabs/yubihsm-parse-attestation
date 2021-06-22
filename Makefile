UNAME := $(shell uname)

.PHONY: build
build:
	go build -ldflags "-w -s" -o build/yubihsm-parse-attestation .

.PHONY: build-xp
build-xp:
	GOOS=darwin GOARCH=amd64 go build -ldflags "-w -s" -o build/yubihsm-parse-attestation_darwin_amd64
	GOOS=darwin GOARCH=arm64 go build -ldflags "-w -s" -o build/yubihsm-parse-attestation_darwin_arm64
	GOOS=linux GOARCH=amd64 go build -ldflags "-w -s" -o build/yubihsm-parse-attestation_linux_amd64
	GOOS=linux GOARCH=arm64 go build -ldflags "-w -s" -o build/yubihsm-parse-attestation_linux_arm64
	GOOS=windows GOARCH=amd64 go build -ldflags "-w -s" -o build/yubihsm-parse-attestation_windows_amd64.exe

.PHONY: release
release: build-xp
ifeq ($(UNAME), Darwin)
	cd build && shasum -a 256 yubihsm-parse-attestation_*64* > sha256sums
else
	cd build && sha256sum yubihsm-parse-attestation_*64* > sha256sums
endif
