package image

import (
	"golang.org/x/time/rate"
	"io"
	"time"
)

type progressReader struct {
	in             io.ReadCloser
	size           int64
	current        int64
	lastUpdate     int64
	rateLimiter    *rate.Limiter // todo 限制修改进度的频率
	updateProgress func(current, size int64, speed float64)
	read           int64
	start          time.Time
}

func NewProgressReader(in io.ReadCloser, size int64,
	updateProgress func(current, size int64, speed float64)) io.ReadCloser {
	return &progressReader{
		in:             in,
		size:           size,
		updateProgress: updateProgress,
		//progress:    progress,
		rateLimiter: rate.NewLimiter(rate.Every(10*time.Millisecond), 1),
	}
}

func (p *progressReader) Read(buf []byte) (n int, err error) {

	read, err := p.in.Read(buf)
	p.current += int64(read)
	p.read += int64(read)
	updateEvery := int64(1024 * 512) //512kB
	if p.size > 0 {
		if increment := int64(0.01 * float64(p.size)); increment < updateEvery {
			updateEvery = increment
		}
	}
	now := time.Now()
	if p.start.IsZero() {
		p.start = now
	}
	if p.updateProgress != nil {
		if p.current-p.lastUpdate > updateEvery || err != nil {
			//fmt.Println(p.speedLimiter.Allow() )
			speed := float64(p.read) / now.Sub(p.start).Seconds()
			if p.current == p.size {
				p.updateProgress(p.current, p.size, speed)
			} else if err != nil && read == 0 || p.rateLimiter.Allow() {
				p.updateProgress(p.current, p.size, speed)
			}

			p.lastUpdate = p.current
		}
	}

	return read, err
}

func (p *progressReader) Close() error {
	if p.current < p.size {
		p.current = p.size
		if p.updateProgress != nil {
			p.updateProgress(p.current, p.size, 0)
		}
	}
	return p.in.Close()
}
