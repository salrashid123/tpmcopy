module main

go 1.23.0

toolchain go1.24.0

require (
	github.com/foxboron/go-tpm-keyfiles v0.0.0-20250520203025-c3c3a4ec1653
	github.com/google/go-tpm v0.9.5
	github.com/google/go-tpm-tools v0.4.5
	github.com/salrashid123/signer/tpm v0.0.0-20250310124309-f5d5ec4c8edc
)

require (
	github.com/google/go-configfs-tsm v0.3.3 // indirect
	golang.org/x/crypto v0.40.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
)

replace github.com/salrashid123/tpmcopy => ../
