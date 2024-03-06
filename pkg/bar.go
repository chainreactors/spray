package pkg

import (
	"github.com/chainreactors/go-metrics"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

func NewBar(u string, total int, stat *Statistor, p *mpb.Progress) *Bar {
	m := metrics.NewMeter()
	metrics.Register(u, m)

	// 在mpb v8中，Name装饰器的使用方式略有不同
	bar := p.AddBar(int64(total),
		mpb.BarFillerClearOnComplete(),
		mpb.BarRemoveOnComplete(),
		mpb.PrependDecorators(
			// 显示自定义的信息，比如下载速度和进度
			decor.Name(u, decor.WC{W: len(u) + 1, C: decor.DindentRight}), // 这里调整了装饰器的参数
			decor.Counters(0, "% d/% d"),
		),
		mpb.AppendDecorators(
			// 显示经过的时间
			decor.Elapsed(decor.ET_STYLE_GO, decor.WC{W: 4}),
		),
	)

	return &Bar{
		url: u,
		bar: bar,
		m:   m,
	}
}

type Bar struct {
	url string
	bar *mpb.Bar
	m   metrics.Meter
}

func (bar *Bar) Done() {
	bar.m.Mark(1)
	bar.bar.Increment()
}

func (bar *Bar) Close() {
	//metrics.Unregister(bar.url)
	// 标记进度条为完成状态
	//bar.bar.Abort(false)
}
