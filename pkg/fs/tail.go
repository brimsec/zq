package fs

import (
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
	"github.com/rjeczalik/notify"
)

var ErrIsDir = errors.New("path is a directory")

type TFile struct {
	f      *os.File
	events chan notify.EventInfo
}

func TailFile(name string) (*TFile, error) {
	info, err := os.Stat(name)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, ErrIsDir
	}
	f, err := OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	events := make(chan notify.EventInfo)
	if err := notify.Watch(name, events, notify.Write); err != nil {
		return nil, err
	}
	return &TFile{f, events}, nil
}

func (t *TFile) Read(b []byte) (int, error) {
read:
	n, err := t.f.Read(b)
	if err == io.EOF {
		if n > 0 {
			return n, nil
		}
		if err := t.waitWrite(); err != nil {
			return 0, err
		}
		goto read
	}
	if errors.Is(err, os.ErrClosed) {
		err = io.EOF
	}
	return n, err
}

func (t *TFile) waitWrite() error {
	_, ok := <-t.events
	if !ok {
		return io.EOF
	}
	return nil
}

func (t *TFile) Stop() {
	notify.Stop(t.events)
	close(t.events)
}

func (t *TFile) Close() error {
	return t.f.Close()
}

type FileOp int

const (
	FileOpCreated FileOp = iota
	FileOpExisting
	FileOpRemoved
)

func (o FileOp) Exists() bool {
	return o == FileOpCreated || o == FileOpExisting
}

type FileEvent struct {
	Name string
	Op   FileOp
	Err  error
}

// DirWatcher observes a directory and will emit events when files are added
// or removed. When open for the first time this will emit an event for
// every existing file.
type DirWatcher struct {
	Events chan FileEvent

	dir     string
	watched map[string]struct{}
	watcher *fsnotify.Watcher
}

func NewDirWatcher(dir string) (*DirWatcher, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("provided path must be a directory")
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	w := &DirWatcher{
		Events:  make(chan FileEvent),
		dir:     dir,
		watched: make(map[string]struct{}),
		watcher: watcher,
	}
	if err := w.watcher.Add(w.dir); err != nil {
		return nil, err
	}
	go func() {
		err := w.run()
		if errc := w.watcher.Close(); err == nil {
			err = errc
		}
		if err != nil {
			w.Events <- FileEvent{Err: err}
		}
		close(w.Events)
	}()
	return w, nil
}

func (w *DirWatcher) run() error {
	if err := w.poll(); err != nil {
		return err
	}
	for ev := range w.watcher.Events {
		switch {
		case ev.Op&fsnotify.Create == fsnotify.Create:
			if err := w.addFile(ev.Name); err != nil {
				return err
			}
		case ev.Op&fsnotify.Rename == fsnotify.Rename, ev.Op&fsnotify.Remove == fsnotify.Remove:
			if err := w.removeFile(ev.Name); err != nil {
				return err
			}
		}
	}
	// watcher has been closed, poll once more to make sure we haven't missed
	// any files due to race.
	return w.poll()
}

func (w *DirWatcher) addFile(name string) error {
	p, err := filepath.Abs(name)
	if err != nil {
		return err
	}
	if _, ok := w.watched[p]; !ok {
		w.watched[p] = struct{}{}
		w.Events <- FileEvent{Name: p, Op: FileOpCreated}
	}
	return nil
}

func (w *DirWatcher) removeFile(name string) error {
	p, err := filepath.Abs(name)
	if err != nil {
		return err
	}
	if _, ok := w.watched[p]; ok {
		delete(w.watched, p)
		w.Events <- FileEvent{Name: p, Op: FileOpRemoved}
	}
	return nil
}

func (w *DirWatcher) poll() error {
	infos, err := ioutil.ReadDir(w.dir)
	if err != nil {
		return err
	}
	for _, info := range infos {
		if info.IsDir() {
			continue
		}
		if err := w.addFile(filepath.Join(w.dir, info.Name())); err != nil {
			return err
		}
	}
	return nil
}

func (w *DirWatcher) Stop() error {
	return w.watcher.Close()
}
