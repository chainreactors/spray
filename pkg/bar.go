package pkg

import (
	"fmt"
	"github.com/gosuri/uiprogress"
	"io"
	"time"
)

func NewBar(u string, total int, progress *uiprogress.Progress) *Bar {
	bar := &Bar{
		Bar:    progress.AddBar(total),
		url:    u,
		writer: progress.Bypass(),
		spend:  1,
	}

	bar.AppendCompleted()
	bar.PrependElapsed()
	bar.PrependFunc(func(b *uiprogress.Bar) string {
		return fmt.Sprintf("%v/s", bar.Current()/bar.spend)
	})

	bar.PrependFunc(func(b *uiprogress.Bar) string {
		return u
	})

	go func() {
		for !bar.close {
			select {
			case <-time.After(time.Duration(250) * time.Millisecond):
				bar.spend++
			}
		}
	}()
	return bar
}

type Bar struct {
	spend  int
	url    string
	close  bool
	writer io.Writer
	*uiprogress.Bar
}

func (bar *Bar) Done() {
	bar.Incr()
}

func (bar *Bar) Print(s string) {
	fmt.Fprintln(bar.writer, s)
}

func (bar *Bar) Close() {
	bar.close = true
}
