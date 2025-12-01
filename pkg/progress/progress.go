package progress

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

const (
	cursorHide = "\033[?25l"
	cursorShow = "\033[?25h"
)

type Writer struct {
	out        io.Writer
	mu         sync.Mutex
	lastLen    int
	isTerminal bool
	width      int

	// Rate limiting to avoid flickering
	minInterval time.Duration
	lastUpdate  time.Time
}

func New(out io.Writer) *Writer {
	w := &Writer{
		out:         out,
		minInterval: 50 * time.Millisecond,
	}

	if f, ok := out.(*os.File); ok {
		w.isTerminal = term.IsTerminal(int(f.Fd()))
		if w.isTerminal {
			w.width, _, _ = term.GetSize(int(f.Fd()))
			fmt.Fprint(out, cursorHide) // Hide on start
		}
	}

	return w
}

var doneOnce sync.Once

// Done restores cursor - MUST be called, typically via defer
func (w *Writer) Done() {
	doneOnce.Do(
		func() {
			if w.isTerminal {
				w.Clear()
				fmt.Fprint(w.out, cursorShow)
			}
		},
	)
}

// Progress updates the current line (for scanning status, etc.)
func (w *Writer) Progress(format string, args ...any) {
	if !w.isTerminal {
		return // Skip progress output for non-terminals (pipes, files)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// Rate limit updates
	now := time.Now()
	if now.Sub(w.lastUpdate) < w.minInterval {
		return
	}
	w.lastUpdate = now

	msg := fmt.Sprintf(format, args...)

	// Truncate to terminal width
	if w.width > 0 && len(msg) > w.width-1 {
		msg = msg[:w.width-4] + "..."
	}

	// Clear previous content and write new
	clearLen := w.lastLen - len(msg)
	if clearLen < 0 {
		clearLen = 0
	}

	fmt.Fprintf(w.out, "\r%s%s", msg, strings.Repeat(" ", clearLen))
	w.lastLen = len(msg)
}

// Clear removes the progress line
func (w *Writer) Clear() {
	if !w.isTerminal {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	fmt.Fprintf(w.out, "\r%s\r", strings.Repeat(" ", w.lastLen))
	w.lastLen = 0
}

// Println prints a permanent line (clears progress first)
func (w *Writer) Println(format string, args ...any) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Clear progress line if we had one
	if w.isTerminal && w.lastLen > 0 {
		fmt.Fprintf(w.out, "\r%s\r", strings.Repeat(" ", w.lastLen))
		w.lastLen = 0
	}

	fmt.Fprintf(w.out, format+"\n", args...)
}
