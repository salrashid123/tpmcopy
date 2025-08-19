module main

go 1.24.0

require (
	github.com/foxboron/go-tpm-keyfiles v0.0.0-20250520203025-c3c3a4ec1653
	github.com/google/go-tpm v0.9.5
	github.com/google/go-tpm-tools v0.4.5
	github.com/salrashid123/signer v0.9.3
	github.com/salrashid123/tpm2genkey v0.8.0
	github.com/salrashid123/tpmcopy v0.0.0
)

require (
	golang.org/x/crypto v0.40.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
)

replace github.com/salrashid123/tpmcopy => ../
