package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

type execRunner struct{}

// Run executes a command, mirrors its stderr to ours and includes it in the
// error, and returns stdout.
func (execRunner) Run(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute) // luksFormat wipes the device
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderr)
	out, err := cmd.Output()
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return out, fmt.Errorf("%w (%s)", err, lastLine(msg))
		}
	}
	return out, err
}

func lastLine(s string) string {
	l := strings.Split(s, "\n")
	return strings.TrimSpace(l[len(l)-1])
}
