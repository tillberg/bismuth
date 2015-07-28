package bismuth

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

type FileInfoIsh struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func NewFileInfoIsh(p string, stat string) (*FileInfoIsh, error) {
	parts := strings.Split(strings.TrimSpace(stat), ",")
	if len(parts) != 4 {
		return nil, errors.New(fmt.Sprintf("NewFileInfoIsh got bad stat result [%#v] for %s", stat, p))
	}
	textMode := strings.ToLower(parts[0])
	isSymlink := textMode == "symbolic link"
	isDir := textMode == "directory"
	rawMode, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return nil, err
	}
	sizeBytes, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return nil, err
	}
	modTimeUnix, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return nil, err
	}
	modTime := time.Unix(modTimeUnix, 0)
	fi := &FileInfoIsh{}
	fi.name = path.Base(p)
	fi.size = sizeBytes
	fi.mode = os.ModePerm & os.FileMode(rawMode)
	if isSymlink {
		fi.mode |= os.ModeSymlink
	}
	if isDir {
		fi.mode |= os.ModeDir
	}
	fi.modTime = modTime
	return fi, nil
}

func (f *FileInfoIsh) Name() string       { return f.name }
func (f *FileInfoIsh) Size() int64        { return f.size }
func (f *FileInfoIsh) Mode() os.FileMode  { return f.mode }
func (f *FileInfoIsh) ModTime() time.Time { return f.modTime }
func (f *FileInfoIsh) IsDir() bool        { return f.mode.IsDir() }
func (f *FileInfoIsh) Sys() interface{}   { return nil }
