package gotty

import (
	"context"
	"fmt"
	"os"
	"strings"
)

type ProgressMessage struct {
	Id      string
	Prefix  string
	Suffix  string
	Total   int64
	Current int64
}

type Progress struct {
	terminalFd uintptr
	winSize    int
	term       TermInfo
	out        *os.File
	//Total int64
	//Current int64
	Output chan ProgressMessage
	ids    map[string]int
	ctx    context.Context
	cancel context.CancelFunc
}

func NewProgress(ctx context.Context, out *os.File) (*Progress, error) {
	term, err := NewTerm()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	return &Progress{
		term:       term,
		out:        out,
		terminalFd: out.Fd(),
		Output:     make(chan ProgressMessage),
		ctx:        ctx,
		cancel:     cancel,
		ids:        make(map[string]int),
	}, nil
}

func (p *Progress) Run() {
	go func() {
		var msg ProgressMessage
		for {
			select {
			case <-p.ctx.Done():
				return
			case msg = <-p.Output:
				line, ok := p.ids[msg.Id]
				if !ok {
					//for _id, i := range p.ids {
					//	p.ids[_id] = i+1
					//}
					line = len(p.ids)
					p.ids[msg.Id] = line
					fmt.Fprintf(p.out, "\n")
				}
				diff := len(p.ids) - line
				if p.term != nil {
					//_l := len(p.ids) - (line + 1)
					CursorUp(p.out, p.term, diff)
					fmt.Fprintf(p.out, "\r")
					ClearLine(p.out, p.term)
					fmt.Fprintf(p.out, "%s\r", msg.GetString(p))
					CursorDown(p.out, p.term, diff)
				}
			}
		}
	}()
}
func (p *Progress) Cancel() {
	p.cancel()
}

func (msg *ProgressMessage) GetString(p *Progress) string {
	var (
		width = p.width()
		pbBox string
	)
	if msg.Total > 0 {
		percentage := int(float64(msg.Current)/float64(msg.Total)*100) / 2
		if percentage > 50 {
			percentage = 50
		}
		if width > 110 {
			// this number can't be negative gh#7136
			numSpaces := 0
			if 50-percentage > 0 {
				numSpaces = 50 - percentage
			}
			pbBox = fmt.Sprintf("[%s>%s] ", strings.Repeat("=", percentage), strings.Repeat(" ", numSpaces))
		}
	}

	return msg.Prefix + pbBox + msg.Suffix
}

func (p *Progress) width() int {
	if p.winSize != 0 {
		return p.winSize
	}
	ws, err := GetWinsize(p.terminalFd)
	if err == nil {
		return int(ws.Width)
	}
	return 200
}
