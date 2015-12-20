package tunnel

import (
	"io"
)

func Copy(to io.ReadWriter, from io.ReadWriter) error {
	errchan := make(chan error, 2)
	copyFunc := func(dst io.Writer, src io.Reader) {
		_, err := io.Copy(dst, src)
		errchan <- err
	}
	go copyFunc(from, to)
	go copyFunc(to, from)
	return <-errchan
}
