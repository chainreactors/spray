package pkg

import (
	"fmt"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
	"time"
)

func NewBar(u string, total int, stat *Statistor, p *mpb.Progress) *Bar {
	if p == nil {
		return &Bar{
			url: u,
		}
	}
	bar := p.AddBar(int64(total),
		mpb.BarFillerClearOnComplete(),
		mpb.BarRemoveOnComplete(),
		mpb.PrependDecorators(
			decor.Name(u, decor.WC{W: len(u) + 1, C: decor.DindentRight}), // 这里调整了装饰器的参数
			decor.NewAverageSpeed(0, "% .0f/s ", time.Now()),
			decor.Counters(0, "%d/%d"),
			decor.Any(func(s decor.Statistics) string {
				return fmt.Sprintf(" found: %d", stat.FoundNumber)
			}),
		),
		mpb.AppendDecorators(
			decor.Percentage(),
			decor.Elapsed(decor.ET_STYLE_GO, decor.WC{W: 4}),
		),
	)

	return &Bar{
		url: u,
		bar: bar,
		//m:   m,
	}
}

type Bar struct {
	url string
	bar *mpb.Bar
	//m   metrics.Meter
}

func (bar *Bar) Done() {
	//bar.m.Mark(1)
	if bar.bar == nil {
		return
	}
	bar.bar.Increment()
}

func (bar *Bar) Close() {
	//metrics.Unregister(bar.url)
	// 标记进度条为完成状态
	if bar.bar == nil {
		return
	}
	bar.bar.Abort(false)
}
