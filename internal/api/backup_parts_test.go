package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/itsPavanFeed/srustiops-backend/internal/secure"
)

// A downloaded backup in parts opens; parts out of order, from another
// tenant, or missing do not.
func TestBackupFileInParts(t *testing.T) {
	sealer, _ := secure.NewSealer(bytes.Repeat([]byte{7}, 32))
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	tw := tar.NewWriter(zw)
	m := []byte(`{"format":1,"tenant":"acme","tables":{},"objects":{}}`)
	tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o600, Size: int64(len(m))})
	tw.Write(m)
	tw.Close()
	zw.Close()
	data := gz.Bytes()
	cut := len(data) / 2
	chunks := [][]byte{data[:cut], data[cut:]}
	file := func(tenant string, order []int, n int) []byte {
		var f bytes.Buffer
		f.Write(backupFileMagic)
		binary.Write(&f, binary.BigEndian, uint32(n))
		for _, i := range order {
			sealed, _ := sealer.Seal(chunks[i], partAAD(tenant, i, len(chunks)))
			binary.Write(&f, binary.BigEndian, uint64(len(sealed)))
			f.Write(sealed)
		}
		return f.Bytes()
	}
	a, err := OpenBackup(file("acme", []int{0, 1}, 2), sealer, "acme")
	if err != nil || a.Manifest.Tenant != "acme" {
		t.Fatalf("open: %v", err)
	}
	if _, err := OpenBackup(file("acme", []int{1, 0}, 2), sealer, "acme"); err == nil {
		t.Fatal("parts out of order were accepted")
	}
	if _, err := OpenBackup(file("other", []int{0, 1}, 2), sealer, "acme"); err == nil {
		t.Fatal("another tenant's parts were accepted")
	}
	short := file("acme", []int{0, 1}, 2)
	if _, err := OpenBackup(short[:len(short)-10], sealer, "acme"); err == nil || !strings.Contains(err.Error(), "truncated") && !strings.Contains(err.Error(), "damaged") {
		t.Fatalf("a truncated file: %v", err)
	}
}
