package main

import (
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	fullScanDirectory  = "full_scan_data"
	fullScanBatchSize  = 2000
	fullScanMaxTargets = 20_000_000
)

type fullScanFileInfo struct {
	FileName    string           `json:"fileName"`
	CreatedAt   string           `json:"createdAt"`
	UpdatedAt   string           `json:"updatedAt"`
	Status      string           `json:"status"`
	Total       int              `json:"total"`
	Processed   int              `json:"processed"`
	Success     int              `json:"success"`
	Failed      int              `json:"failed"`
	Port        int              `json:"port"`
	Delay       int              `json:"delay"`
	Threads     int              `json:"threads"`
	DataCenters []DataCenterInfo `json:"dataCenters,omitempty"`
}

type fullScanMeta struct {
	fullScanFileInfo
	NextIndex   int
	SourceText  string
	SourceCount int
}

type fullScanRecord struct {
	TargetIndex     int
	IP              string
	IPNumber        uint32
	Success         bool
	DataCenter      string
	DCCountry       string
	Region          string
	City            string
	LatencyMS       int64
	FailureCategory string
	FailureDetail   string
}

var (
	activeFullScanMutex sync.Mutex
	activeFullScanFile  string
)

func fullScanDataDirectory() (string, error) {
	dir, err := filepath.Abs(fullScanDirectory)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	return dir, nil
}

func resolveFullScanPath(fileName string) (string, error) {
	fileName = strings.TrimSpace(fileName)
	if fileName == "" || filepath.Base(fileName) != fileName || !strings.HasSuffix(strings.ToLower(fileName), ".db") {
		return "", fmt.Errorf("全库扫描文件名无效")
	}
	dir, err := fullScanDataDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, fileName), nil
}

func nextFullScanFileName(now time.Time) (string, string, error) {
	dir, err := fullScanDataDirectory()
	if err != nil {
		return "", "", err
	}
	base := "fullscan-" + now.Format("20060102-150405")
	for suffix := 0; suffix < 1000; suffix++ {
		name := base + ".db"
		if suffix > 0 {
			name = fmt.Sprintf("%s-%02d.db", base, suffix)
		}
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return name, path, nil
		}
	}
	return "", "", fmt.Errorf("无法生成新的全库扫描文件名")
}

func openFullScanDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, statement := range []string{
		"PRAGMA busy_timeout = 5000",
		"PRAGMA journal_mode = DELETE",
		"PRAGMA synchronous = NORMAL",
	} {
		if _, err := db.Exec(statement); err != nil {
			db.Close()
			return nil, err
		}
	}
	return db, nil
}

func initFullScanDB(db *sql.DB, fileName, sourceText string, sourceCount, total, threads, port, delay int, now time.Time) error {
	schema := []string{
		`CREATE TABLE scan_meta (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			file_name TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			status TEXT NOT NULL,
			total INTEGER NOT NULL,
			processed INTEGER NOT NULL,
			success INTEGER NOT NULL,
			failed INTEGER NOT NULL,
			next_index INTEGER NOT NULL,
			threads INTEGER NOT NULL,
			port INTEGER NOT NULL,
			delay INTEGER NOT NULL,
			source_count INTEGER NOT NULL,
			source_text TEXT NOT NULL
		)`,
		`CREATE TABLE ip_results (
			target_index INTEGER PRIMARY KEY,
			ip TEXT NOT NULL UNIQUE,
			ip_number INTEGER NOT NULL,
			status TEXT NOT NULL,
			data_center TEXT NOT NULL DEFAULT '',
			dc_country TEXT NOT NULL DEFAULT '',
			region TEXT NOT NULL DEFAULT '',
			city TEXT NOT NULL DEFAULT '',
			latency_ms INTEGER NOT NULL DEFAULT 0,
			failure_category TEXT NOT NULL DEFAULT '',
			failure_detail TEXT NOT NULL DEFAULT '',
			scanned_at TEXT NOT NULL
		)`,
		`CREATE INDEX idx_ip_results_dc ON ip_results(status, data_center, latency_ms)`,
	}
	for _, statement := range schema {
		if _, err := db.Exec(statement); err != nil {
			return err
		}
	}
	stamp := now.Format(time.RFC3339)
	_, err := db.Exec(`INSERT INTO scan_meta
		(id, file_name, created_at, updated_at, status, total, processed, success, failed, next_index, threads, port, delay, source_count, source_text)
		VALUES (1, ?, ?, ?, 'ready', ?, 0, 0, 0, 0, ?, ?, ?, ?, ?)`,
		fileName, stamp, stamp, total, threads, port, delay, sourceCount, sourceText)
	return err
}

func loadFullScanMeta(db *sql.DB) (fullScanMeta, error) {
	var meta fullScanMeta
	err := db.QueryRow(`SELECT file_name, created_at, updated_at, status, total, processed, success, failed,
		next_index, threads, port, delay, source_count, source_text FROM scan_meta WHERE id = 1`).Scan(
		&meta.FileName, &meta.CreatedAt, &meta.UpdatedAt, &meta.Status, &meta.Total,
		&meta.Processed, &meta.Success, &meta.Failed, &meta.NextIndex, &meta.Threads,
		&meta.Port, &meta.Delay, &meta.SourceCount, &meta.SourceText,
	)
	return meta, err
}

func setActiveFullScan(fileName string) {
	activeFullScanMutex.Lock()
	activeFullScanFile = fileName
	activeFullScanMutex.Unlock()
}

func clearActiveFullScan(fileName string) {
	activeFullScanMutex.Lock()
	if activeFullScanFile == fileName {
		activeFullScanFile = ""
	}
	activeFullScanMutex.Unlock()
}

func isActiveFullScan(fileName string) bool {
	activeFullScanMutex.Lock()
	defer activeFullScanMutex.Unlock()
	return activeFullScanFile == fileName
}

func buildFullIPv4Targets(sourceText string) ([]uint32, int, error) {
	entries, err := parseIPList(sourceText)
	if err != nil {
		return nil, 0, err
	}
	targets := make([]uint32, 0, len(entries)*254)
	for _, entry := range entries {
		ip, ipNet, err := net.ParseCIDR(strings.TrimSpace(entry))
		if err != nil {
			continue
		}
		ipv4 := ip.To4()
		if ipv4 == nil {
			continue
		}
		ones, bits := ipNet.Mask.Size()
		if bits != 32 || ones < 0 {
			continue
		}
		base := uint64(binary.BigEndian.Uint32(ipv4) & binary.BigEndian.Uint32(ipNet.Mask))
		addressCount := uint64(1) << uint(32-ones)
		first := base
		last := base + addressCount - 1
		if addressCount > 2 {
			first++
			last--
		}
		if uint64(len(targets))+(last-first+1) > fullScanMaxTargets {
			return nil, len(entries), fmt.Errorf("全库地址超过安全上限 %d 条", fullScanMaxTargets)
		}
		for value := first; value <= last; value++ {
			targets = append(targets, uint32(value))
		}
	}
	if len(targets) == 0 {
		return nil, len(entries), fmt.Errorf("IPv4 地址库中没有可扫描地址")
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i] < targets[j] })
	writeIndex := 1
	for readIndex := 1; readIndex < len(targets); readIndex++ {
		if targets[readIndex] == targets[writeIndex-1] {
			continue
		}
		targets[writeIndex] = targets[readIndex]
		writeIndex++
	}
	return targets[:writeIndex], len(entries), nil
}

func uint32ToIPv4(value uint32) string {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	return net.IP(raw[:]).String()
}

func runFullIPv4ScanNew(ctx context.Context, session *appSession, threads, port, delay int) {
	content, err := getIPListContent("ips-v4.txt", "https://www.baipiao.eu.org/cloudflare/ips-v4")
	if err != nil {
		session.sendWSMessage("error", "读取 IPv4 地址库失败: "+err.Error())
		return
	}
	targets, sourceCount, err := buildFullIPv4Targets(content)
	if err != nil {
		session.sendWSMessage("error", "展开 IPv4 地址库失败: "+err.Error())
		return
	}
	now := time.Now()
	fileName, path, err := nextFullScanFileName(now)
	if err != nil {
		session.sendWSMessage("error", err.Error())
		return
	}
	db, err := openFullScanDB(path)
	if err != nil {
		session.sendWSMessage("error", "创建全库扫描文件失败: "+err.Error())
		return
	}
	if err := initFullScanDB(db, fileName, content, sourceCount, len(targets), threads, port, delay, now); err != nil {
		db.Close()
		_ = os.Remove(path)
		session.sendWSMessage("error", "初始化全库扫描文件失败: "+err.Error())
		return
	}
	runFullIPv4Scan(ctx, session, db, fileName, targets)
}

func runFullIPv4ScanResume(ctx context.Context, session *appSession, fileName string) {
	path, err := resolveFullScanPath(fileName)
	if err != nil {
		session.sendWSMessage("error", err.Error())
		return
	}
	db, err := openFullScanDB(path)
	if err != nil {
		session.sendWSMessage("error", "打开全库扫描文件失败: "+err.Error())
		return
	}
	meta, err := loadFullScanMeta(db)
	if err != nil {
		db.Close()
		session.sendWSMessage("error", "读取全库扫描状态失败: "+err.Error())
		return
	}
	if meta.Status == "completed" {
		db.Close()
		session.sendWSMessage("error", "该全库扫描已经完成，无需继续")
		return
	}
	targets, _, err := buildFullIPv4Targets(meta.SourceText)
	if err != nil {
		db.Close()
		session.sendWSMessage("error", "恢复全库地址失败: "+err.Error())
		return
	}
	if len(targets) != meta.Total {
		db.Close()
		session.sendWSMessage("error", "扫描文件中的地址总数与源数据不一致")
		return
	}
	runFullIPv4Scan(ctx, session, db, fileName, targets)
}

func runFullIPv4Scan(ctx context.Context, session *appSession, db *sql.DB, fileName string, targets []uint32) {
	defer db.Close()
	meta, err := loadFullScanMeta(db)
	if err != nil {
		session.sendWSMessage("error", "读取全库扫描状态失败: "+err.Error())
		return
	}
	setActiveFullScan(fileName)
	defer clearActiveFullScan(fileName)
	if _, err := db.Exec(`UPDATE scan_meta SET status = 'running', updated_at = ? WHERE id = 1`, time.Now().Format(time.RFC3339)); err != nil {
		session.sendWSMessage("error", "更新全库扫描状态失败: "+err.Error())
		return
	}
	meta.Status = "running"
	session.sendWSMessage("full_scan_started", meta.fullScanFileInfo)
	session.sendWSMessage("full_scan_progress", meta.fullScanFileInfo)
	session.sendWSMessage("log", fmt.Sprintf("全库 TCPing 扫描开始：%s，共 %d 个 IPv4", fileName, len(targets)))

	next := meta.NextIndex
	for next < len(targets) && ctx.Err() == nil {
		end := next + fullScanBatchSize
		if end > len(targets) {
			end = len(targets)
		}
		existing, err := loadExistingFullScanIndices(db, next, end)
		if err != nil {
			markFullScanFailed(db)
			session.sendWSMessage("error", "读取扫描断点失败: "+err.Error())
			return
		}
		missing := make([]int, 0, end-next-len(existing))
		for index := next; index < end; index++ {
			if !existing[index] {
				missing = append(missing, index)
			}
		}
		records := scanFullIPv4Batch(ctx, targets, missing, meta.Threads, meta.Port, meta.Delay)
		for _, record := range records {
			existing[record.TargetIndex] = true
		}
		checkpoint := next
		for checkpoint < end && existing[checkpoint] {
			checkpoint++
		}
		inserted, successes, failures, err := persistFullScanBatch(db, records, checkpoint)
		if err != nil {
			markFullScanFailed(db)
			session.sendWSMessage("error", "保存全库扫描结果失败: "+err.Error())
			return
		}
		meta.Processed += inserted
		meta.Success += successes
		meta.Failed += failures
		meta.NextIndex = checkpoint
		meta.UpdatedAt = time.Now().Format(time.RFC3339)
		meta.fullScanFileInfo.Status = "running"
		session.sendWSMessage("full_scan_progress", meta.fullScanFileInfo)
		next = checkpoint
		if checkpoint < end {
			break
		}
	}

	if ctx.Err() != nil || next < len(targets) {
		_, _ = db.Exec(`UPDATE scan_meta SET status = 'paused', updated_at = ? WHERE id = 1`, time.Now().Format(time.RFC3339))
		meta.Status = "paused"
		meta.UpdatedAt = time.Now().Format(time.RFC3339)
		session.sendWSMessage("full_scan_paused", meta.fullScanFileInfo)
		session.sendWSMessage("log", fmt.Sprintf("全库扫描已暂停：%s，已保存 %d/%d", fileName, meta.Processed, meta.Total))
		sendFullScanFiles(session)
		return
	}

	completedAt := time.Now().Format(time.RFC3339)
	if _, err := db.Exec(`UPDATE scan_meta SET status = 'completed', next_index = total, updated_at = ? WHERE id = 1`, completedAt); err != nil {
		markFullScanFailed(db)
		session.sendWSMessage("error", "完成全库扫描文件失败: "+err.Error())
		return
	}
	meta.Status = "completed"
	meta.UpdatedAt = completedAt
	meta.NextIndex = meta.Total
	session.sendWSMessage("full_scan_complete", meta.fullScanFileInfo)
	session.sendWSMessage("log", fmt.Sprintf("全库 TCPing 扫描完成：%s，成功 %d，失败 %d", fileName, meta.Success, meta.Failed))
	sendFullScanFiles(session)
}

func loadExistingFullScanIndices(db *sql.DB, start, end int) (map[int]bool, error) {
	rows, err := db.Query(`SELECT target_index FROM ip_results WHERE target_index >= ? AND target_index < ?`, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	existing := make(map[int]bool, end-start)
	for rows.Next() {
		var index int
		if err := rows.Scan(&index); err != nil {
			return nil, err
		}
		existing[index] = true
	}
	return existing, rows.Err()
}

func scanFullIPv4Batch(ctx context.Context, targets []uint32, indices []int, threads, port, delay int) []fullScanRecord {
	if len(indices) == 0 {
		return nil
	}
	if threads <= 0 {
		threads = 100
	}
	if threads > len(indices) {
		threads = len(indices)
	}
	jobs := make(chan int)
	results := make(chan fullScanRecord, len(indices))
	var workers sync.WaitGroup
	for worker := 0; worker < threads; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				if ctx.Err() != nil {
					return
				}
				ipNumber := targets[index]
				ip := uint32ToIPv4(ipNumber)
				result, category, detail := scanOfficialIP(ctx, ip, port, delay)
				if ctx.Err() != nil {
					return
				}
				record := fullScanRecord{TargetIndex: index, IP: ip, IPNumber: ipNumber, FailureCategory: category, FailureDetail: detail}
				if len(record.FailureDetail) > 1000 {
					record.FailureDetail = record.FailureDetail[:1000]
				}
				if result != nil {
					record.Success = true
					record.DataCenter = result.DataCenter
					record.DCCountry = result.DCCountry
					record.Region = result.Region
					record.City = result.City
					record.LatencyMS = result.TCPDuration.Milliseconds()
				}
				results <- record
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, index := range indices {
			select {
			case <-ctx.Done():
				return
			case jobs <- index:
			}
		}
	}()
	workers.Wait()
	close(results)
	records := make([]fullScanRecord, 0, len(indices))
	for record := range results {
		records = append(records, record)
	}
	return records
}

func persistFullScanBatch(db *sql.DB, records []fullScanRecord, checkpoint int) (int, int, int, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, 0, 0, err
	}
	defer tx.Rollback()
	statement, err := tx.Prepare(`INSERT OR IGNORE INTO ip_results
		(target_index, ip, ip_number, status, data_center, dc_country, region, city, latency_ms, failure_category, failure_detail, scanned_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, 0, 0, err
	}
	defer statement.Close()
	inserted, successes, failures := 0, 0, 0
	stamp := time.Now().Format(time.RFC3339)
	for _, record := range records {
		status := "failed"
		if record.Success {
			status = "success"
		}
		result, err := statement.Exec(record.TargetIndex, record.IP, int64(record.IPNumber), status,
			record.DataCenter, record.DCCountry, record.Region, record.City, record.LatencyMS,
			record.FailureCategory, record.FailureDetail, stamp)
		if err != nil {
			return 0, 0, 0, err
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return 0, 0, 0, err
		}
		if rows == 0 {
			continue
		}
		inserted++
		if record.Success {
			successes++
		} else {
			failures++
		}
	}
	_, err = tx.Exec(`UPDATE scan_meta SET processed = processed + ?, success = success + ?, failed = failed + ?,
		next_index = ?, updated_at = ? WHERE id = 1`, inserted, successes, failures, checkpoint, stamp)
	if err != nil {
		return 0, 0, 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, 0, err
	}
	return inserted, successes, failures, nil
}

func markFullScanFailed(db *sql.DB) {
	_, _ = db.Exec(`UPDATE scan_meta SET status = 'failed', updated_at = ? WHERE id = 1`, time.Now().Format(time.RFC3339))
}

func listFullScanFiles() ([]fullScanFileInfo, error) {
	dir, err := fullScanDataDirectory()
	if err != nil {
		return nil, err
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*.db"))
	if err != nil {
		return nil, err
	}
	files := make([]fullScanFileInfo, 0, len(paths))
	for _, path := range paths {
		db, err := openFullScanDB(path)
		if err != nil {
			continue
		}
		meta, err := loadFullScanMeta(db)
		if err == nil && meta.Status == "running" && !isActiveFullScan(meta.FileName) {
			meta.Status = "paused"
			meta.UpdatedAt = time.Now().Format(time.RFC3339)
			_, _ = db.Exec(`UPDATE scan_meta SET status = 'paused', updated_at = ? WHERE id = 1`, meta.UpdatedAt)
		}
		db.Close()
		if err == nil {
			files = append(files, meta.fullScanFileInfo)
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].CreatedAt > files[j].CreatedAt })
	return files, nil
}

func sendFullScanFiles(session *appSession) {
	files, err := listFullScanFiles()
	if err != nil {
		session.sendWSMessage("error", "读取全库扫描文件列表失败: "+err.Error())
		return
	}
	session.sendWSMessage("full_scan_files", files)
}

func loadFullScanDetails(fileName string) (fullScanFileInfo, error) {
	path, err := resolveFullScanPath(fileName)
	if err != nil {
		return fullScanFileInfo{}, err
	}
	db, err := openFullScanDB(path)
	if err != nil {
		return fullScanFileInfo{}, err
	}
	defer db.Close()
	meta, err := loadFullScanMeta(db)
	if err != nil {
		return fullScanFileInfo{}, err
	}
	rows, err := db.Query(`SELECT data_center, dc_country, city, COUNT(*), MIN(latency_ms)
		FROM ip_results WHERE status = 'success' AND data_center <> ''
		GROUP BY data_center, dc_country, city ORDER BY MIN(latency_ms), data_center`)
	if err != nil {
		return fullScanFileInfo{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var dc DataCenterInfo
		if err := rows.Scan(&dc.DataCenter, &dc.DCCountry, &dc.City, &dc.IPCount, &dc.MinLatency); err != nil {
			return fullScanFileInfo{}, err
		}
		meta.DataCenters = append(meta.DataCenters, dc)
	}
	return meta.fullScanFileInfo, rows.Err()
}

func loadFullScanCandidates(fileName, dataCenter string, limit int) ([]ScanResult, error) {
	path, err := resolveFullScanPath(fileName)
	if err != nil {
		return nil, err
	}
	db, err := openFullScanDB(path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	query := `SELECT ip, data_center, dc_country, region, city, latency_ms FROM ip_results
		WHERE status = 'success' AND data_center = ? ORDER BY latency_ms, ip_number`
	args := []interface{}{strings.ToUpper(strings.TrimSpace(dataCenter))}
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []ScanResult
	for rows.Next() {
		var result ScanResult
		var latencyMS int64
		if err := rows.Scan(&result.IP, &result.DataCenter, &result.DCCountry, &result.Region, &result.City, &latencyMS); err != nil {
			return nil, err
		}
		result.TCPDuration = time.Duration(latencyMS) * time.Millisecond
		result.LatencyStr = fmt.Sprintf("%dms", latencyMS)
		results = append(results, result)
	}
	return results, rows.Err()
}
