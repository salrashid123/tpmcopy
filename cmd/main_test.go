package main

import (
	"bytes"
	"io"
	"testing"

	"os"

	"github.com/stretchr/testify/require"
)

func TestMain(t *testing.T) {
	for _, tc := range []struct {
		Name   string
		Args   []string
		Output string
	}{
		{
			Name:   "version",
			Args:   []string{"--version"},
			Output: "Version: \nDate: \nCommit: \n",
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {

			// Create a pipe
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Restore stdout after the test
			defer func() {
				os.Stdout = oldStdout
			}()
			oldArgs := os.Args
			defer func() { os.Args = oldArgs }()

			os.Args = append(os.Args, tc.Args...)
			exitVal := run()

			require.Equal(t, 0, exitVal)

			w.Close() // Close the writer to signal EOF to the reader

			var buf bytes.Buffer
			_, err := io.Copy(&buf, r)
			if err != nil {
				t.Fatalf("Failed to read captured output: %v", err)
			}

			if buf.String() != tc.Output {
				t.Errorf("Expected output '%s', got '%s'", tc.Output, buf.String())
			}
		})
	}
}
