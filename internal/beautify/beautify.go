package beautify

import (
	"bytes"
	"os/exec"
)

// IsAvailable checks whether js-beautify is in PATH.
func IsAvailable() bool {
	_, err := exec.LookPath("js-beautify")
	return err == nil
}

// Beautify runs js-beautify to format JS code, returning the original content on failure.
func Beautify(js []byte) ([]byte, error) {
	cmd := exec.Command("js-beautify", "-f", "-", "-s", "2", "--stdin")
	cmd.Stdin = bytes.NewReader(js)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &bytes.Buffer{}

	if err := cmd.Run(); err != nil {
		return js, err
	}

	result := out.Bytes()
	if len(result) == 0 {
		return js, nil
	}
	return result, nil
}
