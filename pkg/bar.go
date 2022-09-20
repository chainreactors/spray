package pkg

import (
	"fmt"
	"github.com/gosuri/uiprogress"
	"time"
)

func NewBar(u string, total int, progress *uiprogress.Progress) *Bar {
	bar := &Bar{
		Bar:   progress.AddBar(total),
		url:   u,
		spend: 1,
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
	spend int
	url   string
	close bool
	*uiprogress.Bar
}

func (bar *Bar) Done() {
	bar.Incr()
}

func (bar *Bar) Close() {
	bar.close = true
}
