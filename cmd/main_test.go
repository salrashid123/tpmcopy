package main

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"os"

	"github.com/stretchr/testify/require"
)

const (
	TPMA = "127.0.0.1:2321"
	TPMB = "127.0.0.1:2341"
)

func TestMain(t *testing.T) {

	tempDirA := t.TempDir()
	tempDirB := t.TempDir()
	for _, tc := range []struct {
		Name        string
		Args        []string
		Output      string
		ExpectError bool
	}{
		{
			Name:        "publickey",
			Args:        []string{"--mode=publickey", "--parentKeyType=rsa", fmt.Sprintf("--tpmPublicKeyFile=%s/public.pem", tempDirB), fmt.Sprintf("-tpm-path=%s", TPMB)},
			Output:      fmt.Sprintf("Public Key written to: %s/public.pem\n", tempDirB),
			ExpectError: false,
		},
		{
			Name:        "duplicate_password",
			Args:        []string{"--mode=duplicate", "--secret=../testdata/certs/key_rsa.pem", "--password=bar", "--tpmPublicKeyFile=/tmp/public.pem", fmt.Sprintf("--out=%s/out.json", tempDirA), fmt.Sprintf("-tpm-path=%s", TPMA)},
			Output:      fmt.Sprintf("Duplicate Key written to: %s/out.json\n", tempDirA),
			ExpectError: false,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {

			// Create a pipe
			oldStdout := os.Stdout
			r, w, err := os.Pipe()
			require.NoError(t, err)
			os.Stdout = w

			// Restore stdout after the test
			defer func() {
				os.Stdout = oldStdout
			}()
			oldArgs := os.Args
			defer func() { os.Args = oldArgs }()

			os.Args = append(os.Args, tc.Args...)

			exitVal := run()
			if tc.ExpectError {
				require.Equal(t, 1, exitVal)
			} else {
				require.Equal(t, 0, exitVal)
			}

			err = w.Close()
			require.NoError(t, err)

			var buf bytes.Buffer
			_, err = io.Copy(&buf, r)
			require.NoError(t, err)

			require.Equal(t, tc.Output, buf.String())

			os.Stdout = oldStdout
			os.Args = oldArgs

		})
	}
}
