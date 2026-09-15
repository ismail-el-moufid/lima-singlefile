package iso9660util

import (
	"io"
	"os"
	"path"

	"github.com/diskfs/go-diskfs/filesystem"
	"github.com/diskfs/go-diskfs/filesystem/iso9660"
)

type Entry struct {
	Path   string
	Reader io.Reader
}

// Write streams regular-file entries directly into the output ISO. No workspace
// containing copies of the guest agent or other input assets is created.
func Write(isoPath, label string, layout []Entry) error {
	return writeDirect(isoPath, label, layout)
}

func WriteFile(fs filesystem.FileSystem, pathStr string, r io.Reader) (int64, error) {
	if dir := path.Dir(pathStr); dir != "" && dir != "/" {
		if err := fs.Mkdir(dir); err != nil {
			return 0, err
		}
	}
	f, err := fs.OpenFile(pathStr, os.O_CREATE|os.O_RDWR)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return io.Copy(f, r)
}

func IsISO9660(imagePath string) (bool, error) {
	imageFile, err := os.Open(imagePath)
	if err != nil {
		return false, err
	}
	defer imageFile.Close()

	fileInfo, err := imageFile.Stat()
	if err != nil {
		return false, err
	}
	_, err = iso9660.Read(imageFile, fileInfo.Size(), 0, 0)
	return err == nil, nil
}
