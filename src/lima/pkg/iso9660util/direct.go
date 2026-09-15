package iso9660util

import (
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
)

const sectorSize = 2048

// cidata needs only regular files and directories. Short ISO identifiers plus
// Rock Ridge NM/PX records preserve its case-sensitive names and POSIX modes.
// Keeping names within 128 bytes avoids SUSP continuation areas; rejecting deep
// trees avoids the directory relocation required by ISO9660 beyond eight levels.
type isoNode struct {
	name     string
	id       []byte
	parent   *isoNode
	children []*isoNode
	reader   io.Reader
	dir      bool
	number   uint16
	block    uint32
	size     uint32
}

func isoTree(layout []Entry) (*isoNode, []*isoNode, []*isoNode, error) {
	root := &isoNode{dir: true, id: []byte{0}, number: 1}
	root.parent = root
	nodes := map[string]*isoNode{"": root}
	var files []*isoNode
	for _, entry := range layout {
		if !fs.ValidPath(entry.Path) || entry.Path == "." || strings.ContainsRune(entry.Path, 0) || entry.Reader == nil {
			return nil, nil, nil, fmt.Errorf("invalid ISO entry %q", entry.Path)
		}
		parts := strings.Split(entry.Path, "/")
		if len(parts) > 8 {
			return nil, nil, nil, fmt.Errorf("ISO path exceeds eight levels: %q", entry.Path)
		}
		parent := root
		for i, name := range parts {
			if len(name) > 128 {
				return nil, nil, nil, fmt.Errorf("ISO name exceeds 128 bytes: %q", name)
			}
			key := strings.Join(parts[:i+1], "/")
			dir := i != len(parts)-1
			node, exists := nodes[key]
			if exists {
				if !dir || !node.dir {
					return nil, nil, nil, fmt.Errorf("duplicate or conflicting ISO entry %q", entry.Path)
				}
			} else {
				node = &isoNode{name: name, parent: parent, dir: dir}
				if dir {
					node.id = []byte(fmt.Sprintf("D%07d", len(nodes)))
				} else {
					node.id = []byte(fmt.Sprintf("F%07d.;1", len(nodes)))
					node.reader = entry.Reader
					files = append(files, node)
				}
				nodes[key] = node
				parent.children = append(parent.children, node)
			}
			parent = node
		}
	}
	// ISO path tables require breadth-first ordering, then parent and identifier.
	dirs := []*isoNode{root}
	for i := 0; i < len(dirs); i++ {
		d := dirs[i]
		sort.Slice(d.children, func(i, j int) bool { return string(d.children[i].id) < string(d.children[j].id) })
		for _, child := range d.children {
			if child.dir {
				if len(dirs) == 65535 {
					return nil, nil, nil, fmt.Errorf("too many ISO directories")
				}
				child.number = uint16(len(dirs) + 1)
				dirs = append(dirs, child)
			}
		}
	}
	return root, dirs, files, nil
}

func sectors(size int64) int64 { return (size + sectorSize - 1) / sectorSize }

func both16(b []byte, v uint16) {
	binary.LittleEndian.PutUint16(b[:2], v)
	binary.BigEndian.PutUint16(b[2:4], v)
}

func both32(b []byte, v uint32) {
	binary.LittleEndian.PutUint32(b[:4], v)
	binary.BigEndian.PutUint32(b[4:8], v)
}

func directoryRecord(node *isoNode, id []byte, rr, root bool) []byte {
	b := make([]byte, 33+len(id)+(1-len(id)%2))
	both32(b[2:10], node.block)
	both32(b[10:18], node.size)
	// Fixed valid UTC timestamp keeps generated metadata reproducible.
	copy(b[18:25], []byte{122, 1, 1, 0, 0, 0, 0})
	if node.dir {
		b[25] = 2
	}
	both16(b[28:32], 1)
	b[32] = byte(len(id))
	copy(b[33:], id)
	if rr {
		if root {
			b = append(b, 'S', 'P', 7, 1, 0xbe, 0xef, 0)
			b = append(b, 'E', 'R', 18, 1, 10, 0, 0, 1)
			b = append(b, "RRIP_1991A"...)
		}
		flags := byte(1) // PX
		if len(id) > 1 {
			flags |= 8 // NM
		}
		b = append(b, 'R', 'R', 5, 1, flags)
		px := make([]byte, 36) // RRIP_1991A uses the 36-byte PX format.
		copy(px, []byte{'P', 'X', 36, 1})
		mode, links := uint32(0100644), uint32(1)
		if node.dir {
			mode, links = 0040755, 2
			for _, child := range node.children {
				if child.dir {
					links++
				}
			}
		}
		both32(px[4:12], mode)
		both32(px[12:20], links)
		b = append(b, px...)
		if len(id) > 1 {
			b = append(b, 'N', 'M', byte(5+len(node.name)), 1, 0)
			b = append(b, node.name...)
		}
		b = append(b, 'S', 'T', 4, 1)
	}
	if len(b)%2 != 0 {
		b = append(b, 0)
	}
	b[0] = byte(len(b))
	return b
}

func directoryData(dir *isoNode) []byte {
	var data []byte
	add := func(record []byte) {
		if remaining := sectorSize - len(data)%sectorSize; len(record) > remaining {
			data = append(data, make([]byte, remaining)...)
		}
		data = append(data, record...)
	}
	add(directoryRecord(dir, []byte{0}, true, dir.parent == dir))
	add(directoryRecord(dir.parent, []byte{1}, true, false))
	for _, child := range dir.children {
		add(directoryRecord(child, child.id, true, false))
	}
	return append(data, make([]byte, int(sectors(int64(len(data))))*sectorSize-len(data))...)
}

func pathTable(dirs []*isoNode, order binary.ByteOrder) []byte {
	var data []byte
	for _, dir := range dirs {
		b := make([]byte, 8+len(dir.id)+len(dir.id)%2)
		b[0] = byte(len(dir.id))
		order.PutUint32(b[2:6], dir.block)
		order.PutUint16(b[6:8], dir.parent.number)
		copy(b[8:], dir.id)
		data = append(data, b...)
	}
	return data
}

func volumeDescriptor(root *isoNode, label string, blocks, tableSize, tableL, tableM uint32) []byte {
	b := make([]byte, sectorSize)
	copy(b, []byte{1, 'C', 'D', '0', '0', '1', 1})
	for _, span := range [][2]int{{8, 72}, {190, 813}} {
		for i := span[0]; i < span[1]; i++ {
			b[i] = ' '
		}
	}
	copy(b[8:40], "LIMA")
	copy(b[40:72], label)
	both32(b[80:88], blocks)
	both16(b[120:124], 1)
	both16(b[124:128], 1)
	both16(b[128:132], sectorSize)
	both32(b[132:140], tableSize)
	binary.LittleEndian.PutUint32(b[140:144], tableL)
	binary.BigEndian.PutUint32(b[148:152], tableM)
	copy(b[156:190], directoryRecord(root, []byte{0}, false, false))
	for _, offset := range []int{813, 830, 864} {
		copy(b[offset:offset+16], "2022010100000000")
	}
	copy(b[847:863], "0000000000000000")
	b[881] = 1
	return b
}

func writeDirect(isoPath, label string, layout []Entry) (retErr error) {
	if len(label) > 32 || strings.ContainsRune(label, 0) {
		return fmt.Errorf("invalid ISO volume label %q", label)
	}
	root, dirs, files, err := isoTree(layout)
	if err != nil {
		return err
	}
	tableSize := len(pathTable(dirs, binary.LittleEndian))
	tableL := int64(18) // primary descriptor at 16, terminator at 17
	tableM := tableL + sectors(int64(tableSize))
	next := tableM + sectors(int64(tableSize))
	for _, dir := range dirs {
		dir.block = uint32(next)
		dir.size = uint32(len(directoryData(dir)))
		next += sectors(int64(dir.size))
	}
	out, err := os.OpenFile(isoPath, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer func() {
		if err := out.Close(); retErr == nil {
			retErr = err
		}
		if retErr != nil {
			_ = os.Remove(isoPath)
		}
	}()
	// Readers need neither a size nor Seek. File bytes go straight to their
	// final extents; only small directory metadata is buffered in Go memory.
	for _, file := range files {
		file.block = uint32(next)
		if _, err := out.Seek(next*sectorSize, io.SeekStart); err != nil {
			return err
		}
		const maxFileSize = int64(1<<32 - 1)
		n, err := io.Copy(out, io.LimitReader(file.reader, maxFileSize+1))
		if err != nil {
			return fmt.Errorf("write ISO entry %q: %w", file.name, err)
		}
		if n > maxFileSize {
			return fmt.Errorf("ISO entry %q exceeds 4 GiB minus one byte", file.name)
		}
		file.size = uint32(n)
		blocks := sectors(n)
		if blocks == 0 {
			blocks = 1
		}
		next += blocks
		if next > 1<<32-1 {
			return fmt.Errorf("ISO exceeds the volume size limit")
		}
	}
	if err := out.Truncate(next * sectorSize); err != nil {
		return err
	}
	write := func(block int64, data []byte) error {
		_, err := out.WriteAt(data, block*sectorSize)
		return err
	}
	if err := write(16, volumeDescriptor(root, label, uint32(next), uint32(tableSize), uint32(tableL), uint32(tableM))); err != nil {
		return err
	}
	terminator := make([]byte, sectorSize)
	copy(terminator, []byte{255, 'C', 'D', '0', '0', '1', 1})
	if err := write(17, terminator); err != nil {
		return err
	}
	if err := write(tableL, pathTable(dirs, binary.LittleEndian)); err != nil {
		return err
	}
	if err := write(tableM, pathTable(dirs, binary.BigEndian)); err != nil {
		return err
	}
	for _, dir := range dirs {
		if err := write(int64(dir.block), directoryData(dir)); err != nil {
			return err
		}
	}
	return nil
}
