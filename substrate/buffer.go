
package substrate

import "io"

//go:generate mockgen -destination=buffer_mock_test.go -package $GOPACKAGE . Buffer
//go:generate mockgen -destination=writer_mock_test.go -package $GOPACKAGE io Writer

// Buffer is an interface with some methods of *bytes.Buffer.
type Buffer interface {
	io.Writer
	Len() int
	Bytes() []byte
}
