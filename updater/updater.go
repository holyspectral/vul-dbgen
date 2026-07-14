package updater

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/common"
	"github.com/vul-dbgen/updater/nvd"
)

const (
	flagName      = "updater/last"
	notesFlagName = "updater/notes"
)

type WhitelistEntry struct {
	CVE        string
	AppName    string
	ModuleName string
}

var (
	nvdAppWhitelist = []WhitelistEntry{
		{
			CVE:        "CVE-2025-14847",
			AppName:    "mongodb",
			ModuleName: "mongodb",
		},
	}
)

func IgnoreSeverity(s common.Priority) bool {
	return s != common.Critical && s != common.High && s != common.Medium && s != common.Low
}

// Update fetches all the vulnerabilities from the registered fetchers, upserts
// them into the database and then sends notifications.
func Update(datastore Datastore) bool {
	log.Info("updating vulnerabilities")

	// Distro vulns are streamed and inserted during fetch; only apps and raw
	// files are returned here for the final InsertVulnerabilities call.
	status, appVuls, rawFiles := fetch(datastore)
	if !status {
		log.WithFields(log.Fields{"status": status}).Error("Vulnerability update FAIL")
		return false
	}

	err := datastore.InsertVulnerabilities(nil, appVuls, rawFiles)
	if err != nil {
		log.Errorf("an error occured when inserting vulnerabilities for update: %s", err)
		return false
	}
	appVuls = nil
	rawFiles = nil

	log.Info("update finished")
	return true
}

const cveURLPrefix = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="

func xslateUbuntuUpstream(vuls []common.Vulnerability) []common.AppModuleVul {
	upstream := make([]common.AppModuleVul, 0)
	for _, v := range vuls {
		if v.Namespace == "ubuntu:upstream" {
			for _, ff := range v.FixedIn {
				mv := common.AppModuleVul{
					VulName:     v.Name,
					ModuleName:  ff.Name,
					Description: v.Description,
					Link:        cveURLPrefix + v.Name,
					Severity:    v.Severity,
					AffectedVer: []common.AppModuleVersion{common.AppModuleVersion{OpCode: "lt", Version: ff.Version.String()}},
					FixedVer:    []common.AppModuleVersion{common.AppModuleVersion{OpCode: "gteq", Version: ff.Version.String()}},
				}
				upstream = append(upstream, mv)
			}
		}
	}
	return upstream
}

// writeFetcherVuls writes processed vulnerability data as newline-delimited JSON
// to a temp file and returns the path. The in-memory slice becomes GC-eligible
// once this returns.
func writeFetcherVuls(vuls []*common.Vulnerability) (string, error) {
	f, err := os.CreateTemp("", "fetcher-vul-*.json")
	if err != nil {
		return "", err
	}
	name := f.Name()
	bw := bufio.NewWriter(f)
	enc := json.NewEncoder(bw)
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(name)
		}
	}()
	for _, v := range vuls {
		if err := enc.Encode(v); err != nil {
			return "", err
		}
	}
	if err := bw.Flush(); err != nil {
		return "", err
	}
	ok = true
	return name, nil
}

// streamFetcherVuls calls fn for each vulnerability decoded from path.
// Only one Vulnerability is decoded into memory at a time.
func streamFetcherVuls(path string, fn func(*common.Vulnerability) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	for dec.More() {
		var v common.Vulnerability
		if err := dec.Decode(&v); err != nil {
			return err
		}
		if err := fn(&v); err != nil {
			return err
		}
	}
	return nil
}

func fetchDistroVul() (bool, []string) {
	log.Info()

	parallelism := 2
	if v := os.Getenv("FETCHER_PARALLELISM"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			parallelism = n
		}
	}
	if parallelism > len(fetchers) {
		parallelism = len(fetchers)
	}
	log.WithField("parallelism", parallelism).Info("Distro fetcher parallelism")

	status := true
	sem := make(chan struct{}, parallelism)
	responseC := make(chan *FetcherResponse, len(fetchers))

	// Fetch updates in parallel with concurrency limit.
	for n, f := range fetchers {
		go func(name string, fetcher Fetcher) {
			sem <- struct{}{}
			defer func() { <-sem }()

			response, err := fetcher.FetchUpdate()
			if err != nil {
				log.WithFields(log.Fields{"name": name, "error": err}).Error("Distro CVE update FAIL")
				status = false
				responseC <- nil
				return
			}
			responseC <- &response
		}(n, f)
	}

	// Collect results: write each fetcher's output to disk immediately so the
	// in-memory slice is freed rather than accumulated across all fetchers.
	var vulFiles []string
	for i := 0; i < len(fetchers); i++ {
		resp := <-responseC
		if resp != nil {
			processed := doVulnerabilitiesNamespacing(resp.Vulnerabilities)
			path, err := writeFetcherVuls(processed)
			if err != nil {
				log.WithError(err).Error("Failed to write fetcher vulns to disk")
				status = false
			} else {
				vulFiles = append(vulFiles, path)
				log.WithFields(log.Fields{"path": path, "count": len(processed)}).Debug("Wrote fetcher vulns to disk")
			}
			// processed slice is GC-eligible here
		}
	}

	close(responseC)
	return status, vulFiles
}

func fetchAppVul() (bool, []*common.AppModuleVul) {
	log.Info()

	var appVuls []*common.AppModuleVul

	for name, f := range appFetchers {
		start := time.Now()
		log.WithField("name", name).Info("Start app vulnerability fetcher")
		response, err := f.FetchUpdate()
		if err != nil {
			log.WithFields(log.Fields{"name": name, "error": err}).Error("App CVE update FAIL")
			return false, nil
		} else {
			appVuls = append(appVuls, response.Vulnerabilities...)
			log.WithFields(log.Fields{
				"name":            name,
				"vulnerabilities": len(response.Vulnerabilities),
				"elapsed":         time.Since(start).String(),
			}).Info("App vulnerability fetcher done")
		}
	}

	return true, appVuls
}

func correctAppAffectedVersion(appVuls []*common.AppModuleVul) {
	start := time.Now()
	updated := 0
	checked := 0
	log.WithField("apps", len(appVuls)).Info("Start correcting app affected versions")
	for i, app := range appVuls {
		if len(app.AffectedVer) == 0 || len(app.FixedVer) == 0 {
			if affects, fixes, ok := nvd.NVD.GetAffectedVersion(app.VulName); ok {
				// log.WithFields(log.Fields{"name": app.VulName, "affects": affects, "fixes": fixes}).Info("jar update")
				if len(app.AffectedVer) == 0 {
					app.AffectedVer = make([]common.AppModuleVersion, 0)
					for _, v := range affects {
						ver := parseAffectedVersion(v)
						app.AffectedVer = append(app.AffectedVer, ver)
					}
				}

				if len(app.FixedVer) == 0 {
					app.FixedVer = make([]common.AppModuleVersion, 0)
					for _, v := range fixes {
						ver := parseAffectedVersion(v)
						app.FixedVer = append(app.FixedVer, ver)
					}
				}
				updated++
			}
		}
		checked++
		if (i+1)%1000 == 0 {
			log.WithFields(log.Fields{
				"processed": i + 1,
				"total":     len(appVuls),
				"updated":   updated,
				"elapsed":   time.Since(start).String(),
			}).Info("Correcting app affected versions progress")
		}
	}
	log.WithFields(log.Fields{
		"processed": checked,
		"updated":   updated,
		"elapsed":   time.Since(start).String(),
	}).Info("Finished correcting app affected versions")
}

func fetchRawData() (bool, []*common.RawFile) {
	log.Info()

	status := true
	var rawFiles []*common.RawFile
	var responseR = make(chan *RawFetcherResponse, 0)

	for n, f := range rawFetchers {
		go func(name string, fetcher RawFetcher) {
			response, err := fetcher.FetchUpdate()
			if err != nil {
				log.WithFields(log.Fields{"name": name, "error": err}).Error("RAW update FAIL")
				status = false
				responseR <- nil
				return
			}

			responseR <- &response
		}(n, f)
	}

	// Collect results of updates.
	for i := 0; i < len(rawFetchers); i++ {
		resp := <-responseR
		if resp != nil {
			rawFiles = append(rawFiles, &common.RawFile{Name: resp.Name, Raw: resp.Raw})
		}
	}

	close(responseR)
	return status, rawFiles
}

func parseAffectedVersion(str string) common.AppModuleVersion {
	var vo string

	if strings.Contains(str, "||") {
		vo += "or"
		str = strings.TrimLeft(str, "||")
	}
	if strings.Contains(str, "<") {
		vo += "lt"
		str = strings.TrimLeft(str, "<")
	} else if strings.Contains(str, ">") {
		vo += "gt"
		str = strings.TrimLeft(str, ">")
	}
	if strings.Contains(str, "=") {
		vo += "eq"
		str = strings.TrimLeft(str, "=")
	}

	mv := common.AppModuleVersion{OpCode: vo, Version: str}
	return mv
}

// The meta map keeps the NVD score or score from other feeds
func enrichAppMeta(meta *common.NVDMetadata, v *common.AppModuleVul) {
	if meta.CVSSv3.Score == 0 {
		meta.CVSSv3.Score = v.ScoreV3
		meta.CVSSv3.Vectors = v.VectorsV3
	}
	if meta.CVSSv2.Score == 0 {
		meta.CVSSv2.Score = v.Score
		meta.CVSSv2.Vectors = v.Vectors
	}
	if meta.Severity == "" || meta.Severity == common.Unknown {
		meta.Severity = v.Severity
	}
	if meta.PublishedDate.IsZero() {
		meta.PublishedDate = v.IssuedDate
	}
	if meta.LastModifiedDate.IsZero() {
		meta.LastModifiedDate = v.LastModDate
	}
	if len(meta.Description) == 0 {
		meta.Description = v.Description
	}
}

func enrichDistroMeta(meta *common.NVDMetadata, v *common.Vulnerability, cve *common.CVE) {
	if meta.CVSSv3.Score == 0 {
		meta.CVSSv3 = cve.CVSSv3
	}
	if meta.CVSSv2.Score == 0 {
		meta.CVSSv2 = cve.CVSSv2
	}
	if meta.Severity == "" || meta.Severity == common.Unknown {
		meta.Severity = v.Severity
	}
	if meta.PublishedDate.IsZero() {
		meta.PublishedDate = v.IssuedDate
	}
	if meta.LastModifiedDate.IsZero() {
		meta.LastModifiedDate = v.LastModDate
	}
	if len(meta.Description) == 0 {
		meta.Description = v.Description
	}
	// Only use the link from CVD, don't copy here
}

func fixSeverityScore(feedSeverity common.Priority, maxCVSSv2, maxCVSSv3 *common.CVSS) common.Priority {
	// For NVSHAS-4709, always set the severity by CVSS scores
	var severity common.Priority
	if maxCVSSv3.Score >= 9 || maxCVSSv2.Score >= 9 {
		severity = common.Critical
	} else if maxCVSSv3.Score >= 7 || maxCVSSv2.Score >= 7 {
		severity = common.High
	} else if maxCVSSv3.Score >= 4 || maxCVSSv2.Score >= 4 {
		severity = common.Medium
	} else if maxCVSSv3.Score >= 1 || maxCVSSv2.Score >= 1 {
		severity = common.Low
	} else {
		severity = feedSeverity
	}

	if maxCVSSv3.Score == 0 {
		switch severity {
		case common.Critical:
			maxCVSSv3.Score = 9
		case common.High:
			maxCVSSv3.Score = 7
		case common.Medium:
			maxCVSSv3.Score = 4
		case common.Low:
			maxCVSSv3.Score = 1
		}
	}
	if maxCVSSv2.Score == 0 {
		switch severity {
		case common.Critical:
			maxCVSSv2.Score = 9
		case common.High:
			maxCVSSv2.Score = 7
		case common.Medium:
			maxCVSSv2.Score = 4
		case common.Low:
			maxCVSSv2.Score = 1
		}
	}
	return severity
}

// assignMetadata streams distro vulnerabilities from disk files to avoid holding
// all data in RAM simultaneously. Distro vulns are inserted directly into the
// datastore per-file batch during pass 2, so the caller receives only app vulns.
func assignMetadata(vulFiles []string, apps []*common.AppModuleVul, datastore Datastore) []*common.AppModuleVul {
	cveMap := make(map[string]*common.NVDMetadata)
	start := time.Now()
	log.WithFields(log.Fields{
		"distroFiles": len(vulFiles),
		"appVuls":     len(apps),
	}).Info("Start assigning metadata")

	// ── PASS 1: distro — stream from files to build cveMap ──────────────────
	distroProcessed := 0
	for _, path := range vulFiles {
		func() {
			if err := streamFetcherVuls(path, func(v *common.Vulnerability) error {
				cves := []common.CVE{{Name: v.Name}}
				if len(v.CVEs) > 0 {
					cves = v.CVEs
				}
				for _, cve := range cves {
					common.DEBUG_VULN(v, "pre distro")
					key := fmt.Sprintf("%s:%s", v.Namespace, cve.Name)
					if meta, ok := cveMap[key]; ok {
						enrichDistroMeta(meta, v, &cve)
					} else {
						meta, ok := nvd.NVD.GetMetadata(cve.Name)
						if ok {
							enrichDistroMeta(meta, v, &cve)
						} else {
							meta = &common.NVDMetadata{
								CVSSv3:           cve.CVSSv3,
								CVSSv2:           cve.CVSSv2,
								Severity:         v.Severity,
								PublishedDate:    v.IssuedDate,
								LastModifiedDate: v.LastModDate,
							}
						}
						cveMap[key] = meta
					}
				}
				distroProcessed++
				if distroProcessed%10000 == 0 {
					log.WithFields(log.Fields{
						"phase":     "distro-pass1",
						"processed": distroProcessed,
						"cveMap":    len(cveMap),
						"elapsed":   time.Since(start).String(),
					}).Info("Assign metadata progress")
				}
				return nil
			}); err != nil {
				log.WithFields(log.Fields{"path": path, "error": err}).Error("Stream distro vuls pass1 failed")
			}
		}()
	}

	// ── PASS 1: apps (in memory, smaller dataset) ────────────────────────────
	for i, app := range apps {
		cves := []string{app.VulName}
		if len(app.CVEs) > 0 {
			cves = append(cves, app.CVEs...)
		}
		for _, cve := range cves {
			common.DEBUG_VULN(app, "pre app")
			if meta, ok := cveMap[cve]; ok {
				enrichAppMeta(meta, app)
			} else {
				meta, ok := nvd.NVD.GetMetadata(cve)
				if ok {
					enrichAppMeta(meta, app)
				} else {
					meta = &common.NVDMetadata{
						CVSSv3:           common.CVSS{Score: app.ScoreV3, Vectors: app.VectorsV3},
						CVSSv2:           common.CVSS{Score: app.Score, Vectors: app.Vectors},
						Severity:         app.Severity,
						PublishedDate:    app.IssuedDate,
						LastModifiedDate: app.LastModDate,
					}
				}
				cveMap[cve] = meta
			}
		}
		if (i+1)%1000 == 0 {
			log.WithFields(log.Fields{
				"phase":     "app-pass1",
				"processed": i + 1,
				"total":     len(apps),
				"cveMap":    len(cveMap),
				"elapsed":   time.Since(start).String(),
			}).Info("Assign metadata progress")
		}
	}

	// Release NVD map between passes; cveMap now has all needed metadata.
	nvd.NVD.Unload()
	runtime.GC()
	log.Info("NVD metadata unloaded before pass 2")

	// ── PASS 2: distro — stream from files, insert per-file batch ───────────
	distroProcessed = 0
	distroKept := 0
	for _, path := range vulFiles {
		var batch []*common.Vulnerability
		func() {
			if err := streamFetcherVuls(path, func(v *common.Vulnerability) error {
				cves := []common.CVE{{Name: v.Name}}
				if len(v.CVEs) > 0 {
					cves = v.CVEs
				}
				cvss3 := v.CVSSv3
				cvss2 := v.CVSSv2
				for _, cve := range cves {
					key := fmt.Sprintf("%s:%s", v.Namespace, cve.Name)
					if meta, ok := cveMap[key]; ok {
						if v.IssuedDate.IsZero() {
							v.IssuedDate = meta.PublishedDate
						}
						if v.LastModDate.IsZero() {
							v.LastModDate = meta.LastModifiedDate
						}
						if len(v.Description) == 0 {
							v.Description = meta.Description
						}
						if len(v.Link) == 0 {
							v.Link = meta.Link
						}
						if cvss3.Score == 0 {
							cvss3 = meta.CVSSv3
						}
						if cvss2.Score == 0 {
							cvss2 = meta.CVSSv2
						}
						if v.Severity == "" || v.Severity == common.Unknown {
							v.Severity = meta.Severity
						}
					}
				}
				severity := fixSeverityScore(v.Severity, &cvss2, &cvss3)
				v.Severity = severity
				v.CVSSv3 = cvss3
				v.CVSSv2 = cvss2
				if !IgnoreSeverity(v.Severity) {
					batch = append(batch, v)
					common.DEBUG_VULN(v, "post distro")
				}
				distroProcessed++
				if distroProcessed%10000 == 0 {
					log.WithFields(log.Fields{
						"phase":     "distro-pass2",
						"processed": distroProcessed,
						"kept":      distroKept + len(batch),
						"elapsed":   time.Since(start).String(),
					}).Info("Assign metadata progress")
				}
				return nil
			}); err != nil {
				log.WithFields(log.Fields{"path": path, "error": err}).Error("Stream distro vuls pass2 failed")
			}
		}()
		if len(batch) > 0 {
			distroKept += len(batch)
			if err := datastore.InsertDistroVulBatch(batch); err != nil {
				log.WithError(err).Error("InsertDistroVulBatch failed")
			}
			batch = nil
			runtime.GC()
		}
	}

	// ── PASS 2: apps ─────────────────────────────────────────────────────────
	outApps := make([]*common.AppModuleVul, 0)
	for i, app := range apps {
		cves := []string{app.VulName}
		if len(app.CVEs) > 0 {
			cves = append(cves, app.CVEs...)
		}
		cvss3 := common.CVSS{Vectors: app.VectorsV3, Score: app.ScoreV3}
		cvss2 := common.CVSS{Vectors: app.Vectors, Score: app.Score}
		for _, cve := range cves {
			if meta, ok := cveMap[cve]; ok {
				if app.IssuedDate.IsZero() {
					app.IssuedDate = meta.PublishedDate
				}
				if app.LastModDate.IsZero() {
					app.LastModDate = meta.LastModifiedDate
				}
				if len(app.Description) == 0 {
					app.Description = meta.Description
				}
				if len(app.Link) == 0 {
					app.Link = meta.Link
				}
				if cvss3.Score == 0 {
					cvss3 = meta.CVSSv3
				}
				if cvss2.Score == 0 {
					cvss2 = meta.CVSSv2
				}
			}
		}
		severity := fixSeverityScore(app.Severity, &cvss2, &cvss3)
		app.Severity = severity
		app.ScoreV3 = cvss3.Score
		app.VectorsV3 = cvss3.Vectors
		app.Score = cvss2.Score
		app.Vectors = cvss2.Vectors
		if !IgnoreSeverity(app.Severity) {
			outApps = append(outApps, app)
			common.DEBUG_VULN(app, "post app")
		}
		if (i+1)%1000 == 0 {
			log.WithFields(log.Fields{
				"phase":     "app-pass2",
				"processed": i + 1,
				"total":     len(apps),
				"kept":      len(outApps),
				"elapsed":   time.Since(start).String(),
			}).Info("Assign metadata progress")
		}
	}

	log.WithFields(log.Fields{
		"distroOut": distroKept,
		"appOut":    len(outApps),
		"cveMap":    len(cveMap),
		"elapsed":   time.Since(start).String(),
	}).Info("Finished assigning metadata")

	return outApps
}

// fetch gets data from the registered fetchers. Distro vulns are written to
// disk as fetchers complete, then streamed through assignMetadata in two passes
// and inserted directly into the datastore — they are never accumulated in RAM.
func fetch(datastore Datastore) (bool, []*common.AppModuleVul, []*common.RawFile) {
	status := true

	status, vulFiles := fetchDistroVul()
	if !status {
		return status, nil, nil
	}
	defer func() {
		for _, path := range vulFiles {
			os.Remove(path)
		}
	}()
	log.WithField("distroFiles", len(vulFiles)).Info("Fetched distro vulnerabilities to disk")

	runtime.GC() // release fetcher-internal allocations before NVD load

	status, rawFiles := fetchRawData()
	if !status {
		return status, nil, nil
	}
	log.WithField("rawFiles", len(rawFiles)).Info("Fetched raw vulnerability files")

	status, appVuls := fetchAppVul()
	if !status {
		return status, nil, nil
	}
	log.WithField("appVuls", len(appVuls)).Info("Fetched app vulnerabilities")

	log.Info("Start loading NVD metadata")
	if err := nvd.NVD.Load(); err != nil {
		log.Errorf("an error occured when loading NVD: %s.", err)
		return false, nil, nil
	}
	log.Info("Finished loading NVD metadata")

	appVuls = injectNvdWhitelistApps(appVuls)
	log.WithField("appVuls", len(appVuls)).Info("Injected NVD whitelist apps")
	correctAppAffectedVersion(appVuls)

	// assignMetadata streams distro vulns from disk and inserts them directly.
	// NVD is unloaded inside assignMetadata between the two passes.
	apps := assignMetadata(vulFiles, appVuls, datastore)
	log.WithField("appVuls", len(apps)).Info("Fetch pipeline complete")

	return status, apps, rawFiles
}

func injectNvdWhitelistApps(appVuls []*common.AppModuleVul) []*common.AppModuleVul {
	exists := make(map[string]struct{}, len(appVuls))
	for _, app := range appVuls {
		key := fmt.Sprintf("%s:%s", app.ModuleName, app.VulName)
		exists[key] = struct{}{}
	}

	for _, cve := range nvdAppWhitelist {
		module := "nvd"
		key := fmt.Sprintf("%s:%s", module, cve)
		if _, ok := exists[key]; ok {
			continue
		}

		meta, ok := nvd.NVD.GetMetadata(cve.CVE)
		if !ok {
			log.WithFields(log.Fields{"cve": cve}).Warn("NVD whitelist CVE not found")
			continue
		}

		mv := common.AppModuleVul{
			VulName:       cve.CVE,
			AppName:       cve.AppName,
			ModuleName:    cve.ModuleName,
			Severity:      meta.Severity,
			CVEs:          []string{cve.CVE},
			Description:   meta.Description,
			Link:          meta.Link,
			ScoreV3:       meta.CVSSv3.Score,
			VectorsV3:     meta.CVSSv3.Vectors,
			Score:         meta.CVSSv2.Score,
			Vectors:       meta.CVSSv2.Vectors,
			IssuedDate:    meta.PublishedDate,
			LastModDate:   meta.LastModifiedDate,
			FixedVer:      []common.AppModuleVersion{},
			AffectedVer:   []common.AppModuleVersion{},
			UnaffectedVer: []common.AppModuleVersion{},
		}

		appVuls = append(appVuls, &mv)
		exists[key] = struct{}{}
	}

	return appVuls
}

func doVulnerabilitiesNamespacing(vulnerabilities []common.Vulnerability) []*common.Vulnerability {
	vulnerabilitiesMap := make(map[string]*common.Vulnerability)

	for _, v := range vulnerabilities {
		featureVersions := v.FixedIn
		v.FixedIn = []common.FeatureVersion{}

		for _, fv := range featureVersions {
			index := fv.Feature.Namespace + ":" + v.Name

			if vulnerability, ok := vulnerabilitiesMap[index]; !ok {
				newVulnerability := v
				newVulnerability.Namespace = fv.Feature.Namespace
				newVulnerability.FixedIn = []common.FeatureVersion{fv}

				vulnerabilitiesMap[index] = &newVulnerability
			} else {
				vulnerability.FixedIn = append(vulnerability.FixedIn, fv)
			}
		}
	}

	// Convert map into a slice.
	var response []*common.Vulnerability
	for _, vulnerability := range vulnerabilitiesMap {
		response = append(response, vulnerability)
	}

	return response
}
