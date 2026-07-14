package common

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"unicode"

	log "github.com/sirupsen/logrus"
)

const FirstYear = 2014

func CreateDBFile(dbFile *DBFile) error {
	log.WithFields(log.Fields{"file": dbFile.Filename}).Info("Create database file")

	header, _ := json.Marshal(dbFile.Key)

	// Stream tar directly into gzip — no separate uncompressed tar buffer.
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	tw := tar.NewWriter(gw)
	for _, file := range dbFile.Files {
		if err := func() error {
			var size int64
			if file.Path != "" {
				info, err := os.Stat(file.Path)
				if err != nil {
					log.WithFields(log.Fields{"path": file.Path, "error": err}).Error("Stat temp file failed")
					return err
				}
				size = info.Size()
			} else {
				size = int64(len(file.Body))
			}
			hdr := &tar.Header{
				Name:     file.Name,
				Mode:     0655,
				Typeflag: '0',
				Size:     size,
			}
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			if file.Path != "" {
				f, err := os.Open(file.Path)
				if err != nil {
					log.WithFields(log.Fields{"path": file.Path, "error": err}).Error("Open temp file failed")
					return err
				}
				defer f.Close()
				if _, err := io.Copy(tw, f); err != nil {
					return err
				}
			} else {
				if _, err := tw.Write(file.Body); err != nil {
					return err
				}
			}
			return nil
		}(); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gw.Close(); err != nil {
		return err
	}

	cipherData, err := encrypt(gzBuf.Bytes(), getCVEDBEncryptKey())
	gzBuf.Reset()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Encrypt tar file fail")
		return err
	}

	// Write header + ciphertext directly to the output file — no intermediate buffer.
	fdb, err := os.Create(dbFile.Filename)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Create db file fail")
		return err
	}
	defer fdb.Close()

	keyLen := int32(len(header))
	if err := binary.Write(fdb, binary.BigEndian, &keyLen); err != nil {
		return err
	}
	if _, err := fdb.Write(header); err != nil {
		return err
	}
	if n, err := fdb.Write(cipherData); err != nil || n != len(cipherData) {
		if err == nil {
			err = io.ErrShortWrite
		}
		log.WithFields(log.Fields{"error": err}).Error("Write file error")
		return err
	}

	log.WithFields(log.Fields{"file": dbFile.Filename, "size": 4 + len(header) + len(cipherData)}).Info("Create database done")
	return nil
}

func ParseYear(name string) (int, error) {
	for i, r := range name {
		if !unicode.IsDigit(r) {
			return strconv.Atoi(name[:i])
		}
	}
	return strconv.Atoi(name)
}
