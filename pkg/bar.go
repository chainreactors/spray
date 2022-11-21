package pkg

import (
	"fmt"
	"github.com/chainreactors/go-metrics"
	"github.com/gosuri/uiprogress"
)

func NewBar(u string, total int, progress *uiprogress.Progress) *Bar {
	bar := &Bar{
		Bar: progress.AddBar(total),
		url: u,
		m:   metrics.NewMeter(),
	}

	metrics.Register(bar.url, bar.m)
	bar.PrependCompleted()
	bar.PrependFunc(func(b *uiprogress.Bar) string {
		return fmt.Sprintf("%f/s %d/%d", bar.m.Rate1(), bar.m.Count(), bar.Bar.Total)
	})
	bar.PrependFunc(func(b *uiprogress.Bar) string {
		return u
	})
	bar.AppendElapsed()

	return bar
}

type Bar struct {
	url   string
	total int
	close bool
	*uiprogress.Bar
	m metrics.Meter
}

func (bar *Bar) Done() {
	bar.m.Mark(1)
	bar.Incr()
}

func (bar *Bar) Close() {
	metrics.Unregister(bar.url)
	bar.close = true
}
