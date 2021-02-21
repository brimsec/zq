package zson

import (
	"bytes"
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/brimsec/zq/zng"
)

var ErrBufferOverflow = errors.New("zson scanner buffer size exceeded")

const primitiveRE = `^(([0-9a-fA-Fx_\$\-\+:eEnumsh./TZµ]+)|true|false|null|-Inf|-inf|\+Inf|\+inf|NaN|nan)`
const indentationRE = `\n\s*`

type Lexer struct {
	reader      io.Reader
	buffer      []byte
	cursor      []byte
	primitive   *regexp.Regexp
	indentation *regexp.Regexp
}

const (
	ReadSize = 64 * 1024
	MaxSize  = 50 * 1024 * 1024
)

func NewLexer(r io.Reader) (*Lexer, error) {
	primitive := regexp.MustCompile(primitiveRE)
	primitive.Longest()
	indentation := regexp.MustCompile(indentationRE)
	indentation.Longest()
	return &Lexer{
		reader:      r,
		buffer:      make([]byte, ReadSize),
		primitive:   primitive,
		indentation: indentation,
	}, nil
}

func roundUp(n int) int {
	size := ReadSize
	for size < n {
		size *= 2
	}
	return size
}

func (l *Lexer) fill(n int) error {
	if n > MaxSize {
		return ErrBufferOverflow
	}
	remaining := len(l.cursor)
	if n >= cap(l.buffer) {
		n = roundUp(n)
		l.buffer = make([]byte, n)
		copy(l.buffer, l.cursor)
	} else if remaining > 0 {
		copy(l.buffer[0:remaining], l.cursor)
	}
	cc, err := io.ReadFull(l.reader, l.buffer[remaining:cap(l.buffer)])
	l.cursor = l.buffer[0 : remaining+cc]
	if err == io.ErrUnexpectedEOF && cc > 0 {
		err = nil
	}
	return err
}

func (l *Lexer) check(n int) error {
	if len(l.cursor) < n {
		if err := l.fill(n); err != nil {
			return err
		}
		if len(l.cursor) < n {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

func (l *Lexer) skip(n int) error {
	if err := l.check(n); err != nil {
		return err
	}
	l.cursor = l.cursor[n:]
	return nil
}

func (l *Lexer) peek() (byte, error) {
	if err := l.check(1); err != nil {
		return 0, err
	}
	return l.cursor[0], nil
}

func (l *Lexer) match(b byte) (bool, error) {
	if err := l.skipSpace(); err != nil {
		return false, err
	}
	return l.matchTight(b)
}

func (l *Lexer) matchTight(b byte) (bool, error) {
	if len(l.cursor) == 0 {
		return false, io.EOF
	}
	if b == l.cursor[0] {
		if err := l.skip(1); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func (l *Lexer) matchBytes(b []byte) (bool, error) {
	if err := l.skipSpace(); err != nil {
		return false, err
	}
	return l.matchBytesTight(b)
}

func (l *Lexer) matchBytesTight(b []byte) (bool, error) {
	n := len(b)
	if err := l.check(n); err != nil {
		return false, err
	}
	ok := bytes.Equal(b, l.cursor[:n])
	if ok {
		l.skip(n)
	}
	return ok, nil
}

func (l *Lexer) scanTo(b byte) ([]byte, error) {
	var out []byte
	for {
		next, err := l.readByte()
		if err != nil {
			return nil, err
		}
		if next == b {
			return out, nil
		}
		out = append(out, next)
		if len(out) > MaxSize {
			return nil, ErrBufferOverflow
		}
	}
}

func (l *Lexer) readByte() (byte, error) {
	if err := l.check(1); err != nil {
		return 0, err
	}
	b := l.cursor[0]
	l.cursor = l.cursor[1:]
	return b, nil
}

func (l *Lexer) peekRune() (rune, int, error) {
	err := l.check(utf8.UTFMax)
	if len(l.cursor) == 0 {
		if err == nil {
			err = io.EOF
		}
		return 0, 0, err
	}
	r, n := utf8.DecodeRune(l.cursor)
	return r, n, nil
}

var slashCommentStart = []byte("//")
var starCommentStart = []byte("/*")

func (l *Lexer) skipSpace() error {
	for {
		r, n, err := l.peekRune()
		if err != nil {
			return err
		}
		if unicode.IsSpace(r) {
			l.skip(n)
			continue
		}
		if r == '/' {
			ok, err := l.matchBytesTight(slashCommentStart)
			if err != nil {
				return err
			}
			if ok {
				if err := l.skipLine(); err != nil {
					return err
				}
				continue
			}
			ok, err = l.matchBytesTight(starCommentStart)
			if err != nil {
				return err
			}
			if ok {
				if err := l.skipMultiLine(); err != nil {
					return err
				}
				continue
			}
		}
		return nil
	}
}

func isNewline(r rune) bool {
	// See http://www.unicode.org/versions/Unicode13.0.0/ch05.pdf#G10213
	switch r {
	case 0x000A, 0x000B, 0x000C, 0x000D, 0x0085, 0x2028, 0x2029:
		return true
	}
	return false
}

func (l *Lexer) skipLine() error {
	for {
		r, n, err := l.peekRune()
		if err != nil {
			return err
		}
		l.skip(n)
		if isNewline(r) {
			return nil
		}
	}
}

func (l *Lexer) skipMultiLine() error {
	for {
		b, err := l.readByte()
		if err != nil {
			return err
		}
		for b == '*' {
			b, err = l.readByte()
			if err != nil {
				return err
			}
			if b == '/' {
				return nil
			}
		}
	}
}

func (l *Lexer) scanString() (string, error) {
	var s strings.Builder
	for {
		c, err := l.peek()
		if err != nil {
			return "", err
		}
		if c == '"' {
			return s.String(), nil
		}
		l.skip(1)
		if c == '\n' {
			return "", errors.New("unescaped linebreak in string literal")
		}
		if c == '\\' {
			c, err = l.readByte()
			if err != nil {
				if err == io.EOF {
					err = errors.New("unterminated string")
				}
				return "", err
			}
			//XXX what about \u{}
			switch c {
			case '"', '\\': // nothing

			case 'b':
				c = '\b'
			case 'f':
				c = '\f'
			case 'n':
				c = '\n'
			case 'r':
				c = '\r'
			case 't':
				c = '\t'
			default:
				s.WriteByte('\\')
			}
		}
		s.WriteByte(c)
	}
}

var newline = []byte{'\n'}

func (l *Lexer) scanBacktickString(keepIndentation bool) (string, error) {
	b, err := l.scanTo('`')
	if err != nil {
		if err == ErrBufferOverflow || err == io.EOF || err == io.ErrUnexpectedEOF {
			err = errors.New("unterminated backtick string")
		}
		return "", err
	}
	if !keepIndentation {
		b = l.indentation.ReplaceAll(b, newline)
		if b[0] == '\n' {
			b = b[1:]
		}
	}
	return string(b), nil
}

func (l *Lexer) scanTypeName() (string, error) {
	var s strings.Builder
	for {
		r, n, err := l.peekRune()
		if err != nil {
			if err == io.EOF {
				return s.String(), nil
			}
			return "", err
		}
		if !zng.TypeChar(r) {
			return s.String(), nil
		}
		s.WriteRune(r)
		l.skip(n)
	}
}

func (l *Lexer) scanIdentifier() (string, error) {
	s, err := l.scanTypeName()
	if err != nil {
		return "", err
	}
	if !zng.IsIdentifier(s) {
		return "", errors.New("malformed identifier")
	}
	return s, nil
}

// peekPrimitive returns a string that may be a candidate for a primitive token
// exlusive of string literals.  This works by scanning forward until we see
// whitespace or EOF while keeping everything buffered.  This could be made more
// efficient by keeping track of the whitespace boundary and only looking for
// it when we're past it (or by implementing a proper DFA for literal matching).
func (l *Lexer) peekPrimitive() (string, error) {
	var err error
	var off int
	for {
		err = l.check(off + utf8.UTFMax)
		if err != nil {
			break
		}
		r, n := utf8.DecodeRune(l.cursor[off:])
		if unicode.IsSpace(r) || r == ',' {
			break
		}
		off += n
	}
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return "", err
	}
	if len(l.cursor) == 0 {
		return "", io.EOF
	}
	return string(l.primitive.Find(l.cursor)), nil
}
