package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/common"
	utils "github.com/vul-dbgen/share"
)

type memDB struct {
	keyVer   common.KeyVersion
	tbPath   string
	tmpPath  string
	osVuls   map[string]*common.VulFull
	appVuls  []*common.AppModuleVul
	rawFiles []*common.RawFile
}

func newMemDb(path string) (*memDB, error) {
	var db memDB
	db.osVuls = make(map[string]*common.VulFull, 0)
	db.keyVer.Keys = make(map[string]string, 0)
	db.keyVer.Shas = make(map[string]string, 0)
	return &db, nil
}

func vulToShort(v *common.VulFull) *common.VulShort {
	var vs = common.VulShort{
		Name:      v.Name,
		Namespace: v.Namespace,
		CPEs:      v.CPEs,
	}
	for _, ft := range v.FixedIn {
		var f common.FeaShort
		f.Name = ft.Name
		f.Version = ft.Version
		f.MinVer = ft.MinVer
		vs.Fixin = append(vs.Fixin, f)
	}
	return &vs
}

func modVulToVulFull(v *common.Vulnerability) *common.VulFull {
	var vv1 common.VulFull
	vv1.Name = v.Name
	vv1.Namespace = v.Namespace
	vv1.Description = v.Description
	vv1.Link = v.Link
	vv1.Severity = v.Severity
	vv1.FeedRating = v.FeedRating
	vv1.CPEs = v.CPEs
	vv1.CVEs = make([]string, len(v.CVEs))
	for i, cve := range v.CVEs {
		vv1.CVEs[i] = cve.Name
	}
	vv1.CVSSv2 = v.CVSSv2
	vv1.CVSSv3 = v.CVSSv3
	vv1.IssuedDate = v.IssuedDate
	vv1.LastModDate = v.LastModDate

	return &vv1
}

func modFeaToFeaFull(fx common.FeatureVersion) common.FeaFull {
	var v1fx = common.FeaFull{
		Name:    fx.Feature.Name,
		Version: fx.Version.String(),
		MinVer:  fx.MinVer.String(),
	}
	return v1fx
}

func splitDb(db *memDB, dbs *dbSpace) (ok bool) {
	if db.osVuls == nil {
		return
	}

	type nsFile struct {
		indexF  *os.File
		indexBW *bufio.Writer
		indexW  io.Writer
		indexH  hash.Hash
		fullF   *os.File
		fullBW  *bufio.Writer
		fullW   io.Writer
		fullH   hash.Hash
	}

	ns := make([]nsFile, dbMax)
	// On any failure path, clean up all temp files whether still open in ns[] or
	// already closed+stored in dbs.buffers. Calling Close/Remove on already-closed
	// files or non-existent paths is safe (errors are ignored).
	defer func() {
		if ok {
			return
		}
		for i := 0; i < dbMax; i++ {
			if ns[i].indexF != nil {
				ns[i].indexF.Close()
				os.Remove(ns[i].indexF.Name())
			}
			if ns[i].fullF != nil {
				ns[i].fullF.Close()
				os.Remove(ns[i].fullF.Name())
			}
			if dbs.buffers[i].indexPath != "" {
				os.Remove(dbs.buffers[i].indexPath)
				dbs.buffers[i].indexPath = ""
			}
			if dbs.buffers[i].fullPath != "" {
				os.Remove(dbs.buffers[i].fullPath)
				dbs.buffers[i].fullPath = ""
			}
		}
		if dbs.appPath != "" {
			os.Remove(dbs.appPath)
			dbs.appPath = ""
		}
	}()

	for i := 0; i < dbMax; i++ {
		indexF, err := os.CreateTemp("", "cvebuf-index-*.tb")
		if err != nil {
			log.WithError(err).Error("splitDb: create index temp file")
			return
		}
		fullF, err := os.CreateTemp("", "cvebuf-full-*.tb")
		if err != nil {
			ns[i].indexF = indexF // let defer close+remove it
			log.WithError(err).Error("splitDb: create full temp file")
			return
		}
		indexH := sha256.New()
		fullH := sha256.New()
		indexBW := bufio.NewWriter(indexF)
		fullBW := bufio.NewWriter(fullF)
		ns[i] = nsFile{
			indexF:  indexF,
			indexBW: indexBW,
			indexW:  io.MultiWriter(indexBW, indexH),
			indexH:  indexH,
			fullF:   fullF,
			fullBW:  fullBW,
			fullW:   io.MultiWriter(fullBW, fullH),
			fullH:   fullH,
		}
	}

	for _, v := range db.osVuls {
		idx := -1
		for i := 0; i < dbMax; i++ {
			if strings.Contains(v.Namespace, dbs.buffers[i].namespace) {
				idx = i
				break
			}
		}
		if idx < 0 {
			log.Error("No known namespace found:", v.Namespace)
			return
		}
		vs := vulToShort(v)
		if b, err := json.Marshal(vs); err == nil {
			fmt.Fprintf(ns[idx].indexW, "%s\n", b)
		}
		if b, err := json.Marshal(v); err == nil {
			fmt.Fprintf(ns[idx].fullW, "%s\n", b)
		}
	}

	for i := 0; i < dbMax; i++ {
		if err := ns[i].indexBW.Flush(); err != nil {
			log.WithError(err).Error("splitDb: flush index buffer")
			return
		}
		if err := ns[i].fullBW.Flush(); err != nil {
			log.WithError(err).Error("splitDb: flush full buffer")
			return
		}
		ns[i].indexF.Close()
		ns[i].fullF.Close()
		dbs.buffers[i].indexPath = ns[i].indexF.Name()
		dbs.buffers[i].fullPath = ns[i].fullF.Name()
		copy(dbs.buffers[i].indexSHA[:], ns[i].indexH.Sum(nil))
		copy(dbs.buffers[i].fullSHA[:], ns[i].fullH.Sum(nil))
	}

	appF, err := os.CreateTemp("", "cvebuf-apps-*.tb")
	if err != nil {
		log.WithError(err).Error("splitDb: create apps temp file")
		return
	}
	appH := sha256.New()
	appBW := bufio.NewWriter(appF)
	appMW := io.MultiWriter(appBW, appH)
	for _, v := range db.appVuls {
		if b, err := json.Marshal(v); err == nil {
			fmt.Fprintf(appMW, "%s\n", b)
		}
	}
	if err := appBW.Flush(); err != nil {
		appF.Close()
		os.Remove(appF.Name())
		log.WithError(err).Error("splitDb: flush apps buffer")
		return
	}
	appF.Close()
	dbs.appPath = appF.Name()
	copy(dbs.appSHA[:], appH.Sum(nil))

	for i, v := range db.rawFiles {
		dbs.rawSHA[i] = sha256.Sum256(v.Raw)
	}

	ok = true
	return
}

var rawFilenames []string = []string{
	common.RHELCpeMapFile,
}

const (
	dbUbuntu = iota
	dbDebian
	dbCentos
	dbAlpine
	dbAmazon
	dbOracle
	dbMariner
	dbSuse
	dbPhoton
	dbRocky
	dbWolfi
	dbChainguard
	dbMax
)

type dbBuffer struct {
	namespace string
	indexFile string
	fullFile  string
	indexPath string
	fullPath  string
	indexSHA  [sha256.Size]byte
	fullSHA   [sha256.Size]byte
}

type dbSpace struct {
	buffers [dbMax]dbBuffer
	appPath string
	appSHA  [sha256.Size]byte
	rawSHA  [][sha256.Size]byte
}

func (db *memDB) UpdateDb(version string) bool {
	// if len(db.vuls) == 0 {
	// 		log.Errorf("CVE update FAIL")
	// 		return false
	// 	}

	var dbs dbSpace
	dbs.buffers[dbUbuntu] = dbBuffer{namespace: "ubuntu", indexFile: "ubuntu_index.tb", fullFile: "ubuntu_full.tb"}
	dbs.buffers[dbDebian] = dbBuffer{namespace: "debian", indexFile: "debian_index.tb", fullFile: "debian_full.tb"}
	dbs.buffers[dbCentos] = dbBuffer{namespace: "centos", indexFile: "centos_index.tb", fullFile: "centos_full.tb"}
	dbs.buffers[dbAlpine] = dbBuffer{namespace: "alpine", indexFile: "alpine_index.tb", fullFile: "alpine_full.tb"}
	dbs.buffers[dbAmazon] = dbBuffer{namespace: "amzn", indexFile: "amazon_index.tb", fullFile: "amazon_full.tb"}
	dbs.buffers[dbOracle] = dbBuffer{namespace: "oracle", indexFile: "oracle_index.tb", fullFile: "oracle_full.tb"}
	dbs.buffers[dbMariner] = dbBuffer{namespace: "mariner", indexFile: "mariner_index.tb", fullFile: "mariner_full.tb"}
	dbs.buffers[dbSuse] = dbBuffer{namespace: "sles", indexFile: "suse_index.tb", fullFile: "suse_full.tb"}
	dbs.buffers[dbPhoton] = dbBuffer{namespace: "photon", indexFile: "photon_index.tb", fullFile: "photon_full.tb"}
	dbs.buffers[dbRocky] = dbBuffer{namespace: "rocky", indexFile: "rocky_index.tb", fullFile: "rocky_full.tb"}
	dbs.buffers[dbWolfi] = dbBuffer{namespace: "wolfi", indexFile: "wolfi_index.tb", fullFile: "wolfi_full.tb"}
	dbs.buffers[dbChainguard] = dbBuffer{namespace: "chainguard", indexFile: "chainguard_index.tb", fullFile: "chainguard_full.tb"}

	dbs.rawSHA = make([][sha256.Size]byte, len(db.rawFiles))

	ok := splitDb(db, &dbs)
	if !ok {
		log.Error("Split database error")
		return false
	}

	log.WithFields(log.Fields{"vuls": len(db.osVuls), "appVuls": len(db.appVuls)}).Info()

	// All vuln data is now on disk; free the in-memory map before compress/encrypt.
	db.osVuls = nil
	runtime.GC()

	var compactDB common.DBFile
	var regularDB common.DBFile

	// Compact database is consumed by scanners running inside controller. This scanner
	// in old versions cannot parse the regular db because of the header size limit
	// No new entries should be added !!!
	{
		keyVer := common.KeyVersion{
			Version:    version,
			UpdateTime: time.Now().Format(time.RFC3339),
			Keys:       db.keyVer.Keys,
			Shas:       make(map[string]string, 0),
		}

		for _, i := range []int{dbUbuntu, dbDebian, dbCentos, dbAlpine} {
			buf := &dbs.buffers[i]
			keyVer.Shas[buf.indexFile] = fmt.Sprintf("%x", buf.indexSHA)
			keyVer.Shas[buf.fullFile] = fmt.Sprintf("%x", buf.fullSHA)
		}
		keyVer.Shas["apps.tb"] = fmt.Sprintf("%x", dbs.appSHA)

		var files []utils.TarFileInfo
		for _, i := range []int{dbUbuntu, dbDebian, dbCentos, dbAlpine} {
			buf := &dbs.buffers[i]
			files = append(files, utils.TarFileInfo{Name: buf.indexFile, Path: buf.indexPath})
			files = append(files, utils.TarFileInfo{Name: buf.fullFile, Path: buf.fullPath})
		}
		files = append(files, utils.TarFileInfo{Name: "apps.tb", Path: dbs.appPath})

		compactDB.Filename = db.tbPath + common.CompactCVEDBName
		compactDB.Key = keyVer
		compactDB.Files = files
	}

	// regular files
	{
		keyVer := common.KeyVersion{
			Version:    version,
			UpdateTime: time.Now().Format(time.RFC3339),
			Keys:       db.keyVer.Keys,
			Shas:       make(map[string]string, 0),
		}

		for i := 0; i < dbMax; i++ {
			buf := &dbs.buffers[i]
			keyVer.Shas[buf.indexFile] = fmt.Sprintf("%x", buf.indexSHA)
			keyVer.Shas[buf.fullFile] = fmt.Sprintf("%x", buf.fullSHA)
		}
		keyVer.Shas["apps.tb"] = fmt.Sprintf("%x", dbs.appSHA)

		var files []utils.TarFileInfo
		for i := 0; i < dbMax; i++ {
			buf := &dbs.buffers[i]
			files = append(files, utils.TarFileInfo{Name: buf.indexFile, Path: buf.indexPath})
			files = append(files, utils.TarFileInfo{Name: buf.fullFile, Path: buf.fullPath})
			log.WithFields(log.Fields{"database": buf.namespace}).Info()
		}
		files = append(files, utils.TarFileInfo{Name: "apps.tb", Path: dbs.appPath})
		log.WithFields(log.Fields{"database": "apps"}).Info()
		for i, v := range db.rawFiles {
			files = append(files, utils.TarFileInfo{Name: v.Name, Body: v.Raw})
			keyVer.Shas[v.Name] = fmt.Sprintf("%x", dbs.rawSHA[i])
			log.WithFields(log.Fields{"database": v.Name, "size": len(v.Raw)}).Info()
		}

		regularDB.Filename = db.tbPath + common.RegularCVEDBName
		regularDB.Key = keyVer
		regularDB.Files = files
	}

	defer func() {
		for i := 0; i < dbMax; i++ {
			os.Remove(dbs.buffers[i].indexPath)
			os.Remove(dbs.buffers[i].fullPath)
		}
		os.Remove(dbs.appPath)
	}()

	for _, dbf := range []*common.DBFile{&compactDB, &regularDB} {
		if err := common.CreateDBFile(dbf); err != nil {
			log.WithError(err).Error("CreateDBFile failed")
			return false
		}
	}

	return true
}

func memdbOpen(path string) (*memDB, error) {
	dir, err := ioutil.TempDir("", "cve")
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to create tmp cve directory")
		return nil, err
	}
	db, dbErr := newMemDb(path)
	db.tbPath = path
	db.tmpPath = dir
	return db, dbErr
}

func (db *memDB) InsertDistroVulBatch(vuls []*common.Vulnerability) error {
	for _, v := range vuls {
		vv1 := modVulToVulFull(v)
		for _, fx := range v.FixedIn {
			v1fx := modFeaToFeaFull(fx)
			vv1.FixedIn = append(vv1.FixedIn, v1fx)
		}
		cveName := fmt.Sprintf("%s:%s", vv1.Namespace, vv1.Name)
		db.osVuls[cveName] = vv1
	}
	return nil
}

func (db *memDB) InsertVulnerabilities(osVuls []*common.Vulnerability, appVuls []*common.AppModuleVul, rawFiles []*common.RawFile) error {
	for _, v := range osVuls {
		vv1 := modVulToVulFull(v)
		for _, fx := range v.FixedIn {
			v1fx := modFeaToFeaFull(fx)
			vv1.FixedIn = append(vv1.FixedIn, v1fx)
		}
		cveName := fmt.Sprintf("%s:%s", vv1.Namespace, vv1.Name)
		db.osVuls[cveName] = vv1
	}
	db.appVuls = appVuls

	db.rawFiles = rawFiles
	// If a raw file is missing, add an empty file
	for _, name := range rawFilenames {
		found := false
		for i, _ := range db.rawFiles {
			if db.rawFiles[i].Name == name {
				found = true
				break
			}
		}
		if !found {
			db.rawFiles = append(db.rawFiles, &common.RawFile{Name: name, Raw: make([]byte, 0)})
		}
	}

	return nil
}

func (db *memDB) Close() {
	os.RemoveAll(db.tmpPath)
}
