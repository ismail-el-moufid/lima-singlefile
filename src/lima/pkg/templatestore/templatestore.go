package templatestore

import (
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/lima-vm/lima/pkg/embeddedassets"
)

type Template struct {
	Name     string `json:"name"`
	Location string `json:"location"`
}

func Read(name string) ([]byte, error) {
	if !fs.ValidPath(name) || name == "." {
		return nil, &fs.PathError{Op: "read", Path: name, Err: fs.ErrInvalid}
	}
	examples, err := embeddedassets.Templates()
	if err != nil {
		return nil, err
	}
	return fs.ReadFile(examples, name+".yaml")
}

const Default = "default"

func Templates() ([]Template, error) {
	examples, err := embeddedassets.Templates()
	if err != nil {
		return nil, err
	}

	var res []Template
	walkDirFn := func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		base := path.Base(p)
		if d.IsDir() || strings.HasPrefix(base, ".") || !strings.HasSuffix(base, ".yaml") {
			return nil
		}
		x := Template{
			// Name is like "default", "debian", "deprecated/centos-7", ...
			Name:     strings.TrimSuffix(p, ".yaml"),
			Location: "template://" + strings.TrimSuffix(p, ".yaml"),
		}
		res = append(res, x)
		return nil
	}
	if err = fs.WalkDir(examples, ".", walkDirFn); err != nil {
		return nil, err
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Name < res[j].Name })
	return res, nil
}
