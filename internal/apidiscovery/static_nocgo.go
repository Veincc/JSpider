//go:build !cgo

package apidiscovery

import "errors"

var errCGORequired = errors.New("API discovery requires a CGO-enabled build")

func CheckAvailable() error {
	return errCGORequired
}

func AnalyzeJavaScript(_ []byte, _ string) ([]StaticEndpoint, error) {
	return nil, errCGORequired
}
