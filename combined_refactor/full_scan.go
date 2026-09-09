package main

import (
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	fullScanDirectory     = "full_scan_data"
	fullScanBatchSize     = 2000
	fullScanMaxTargets    = 20_000_000
	fullScanMinDelay      = 100               // 最小请求间隔（ms），防止被判定为攻击
	fullScanMaxThreads    = 200               // 全库扫描最大并发数，降低同时连接数
	fullScanBatchCooldown = 2 * time.Second   // 批次间冷却时间，降低持续高频请求被风控的风险
	fullScanJitterRange   = 50                // 随机抖动范围（ms），避免请求突发
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

// fullScanSubnetCache 缓存 /24 子网对应的 DC 信息，同子网只做一次 trace 请求
type fullScanSubnetCache struct {
	mu      sync.Mutex
	subnets map[string]*ScanResult
}

func newFullScanSubnetCache() *fullScanSubnetCache {
	return &fullScanSubnetCache{subnets: make(map[string]*ScanResult)}
}

func ipPrefix(ip string) string {
	parts := strings.SplitN(ip, ".", 4)
	if len(parts) >= 3 {
		return parts[0] + "." + parts[1] + "." + parts[2]
	}
	return ip
}

func (c *fullScanSubnetCache) get(ip string) (*ScanResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.subnets[ipPrefix(ip)]
	return r, ok
}

func (c *fullScanSubnetCache) set(ip string, result *ScanResult) {
	prefix := ipPrefix(ip)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.subnets[prefix]; !ok {
		c.subnets[prefix] = result
	}
}

// loadFullScanSubnetCacheFromDB 从已有扫描结果中加载子网缓存（用于断点续扫）
func loadFullScanSubnetCacheFromDB(db *sql.DB) *fullScanSubnetCache {
	cache := newFullScanSubnetCache()
	rows, err := db.Query(`SELECT ip, data_center, dc_country, region, city FROM ip_results
		WHERE status = 'success' AND data_center <> ''`)
	if err != nil {
		return cache
	}
	defer rows.Close()
	for rows.Next() {
		var ip, dc, country, region, city string
		if err := rows.Scan(&ip, &dc, &country, &region, &city); err != nil {
			continue
		}
		cache.set(ip, &ScanResult{
			IP: ip, DataCenter: dc, DCCountry: country, Region: region, City: city,
		})
	}
	return cache
}

// tcpPingIP 仅做 TCP 连接测试，不发 trace 请求（用于子网推断后的快速扫描）
func tcpPingIP(ctx context.Context, ip string, port, delay int) (time.Duration, string, string) {
	dialer := &net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return 0, "tcp_connect_failed", err.Error()
	}
	conn.Close()
	duration := time.Since(start)
	if delay > 0 && duration.Milliseconds() > int64(delay) {
		return duration, "delay_exceeded", fmt.Sprintf("connect=%dms, delay=%dms", duration.Milliseconds(), delay)
	}
	return duration, "", ""
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
	session.sendWSMessage("log", fmt.Sprintf("全库 TCPing 扫描开始：%s，共 %d 个 IPv4，速率限制 %dms/请求，并发 %d，已启用防封禁保护", fileName, len(targets), meta.Delay, meta.Threads))

	// 子网推断缓存：从 DB 加载已有结果，同 /24 子网只做一次 trace
	subnetCache := loadFullScanSubnetCacheFromDB(db)
	// 被封锁信号检测
	consecutiveHighFailureBatches := 0

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
		records := scanFullIPv4Batch(ctx, targets, missing, meta.Threads, meta.Port, meta.Delay, subnetCache)
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

		// 被封锁信号检测：检查是否触发 429 限流
		rateLimitedCount := 0
		for _, record := range records {
			if record.FailureCategory == "rate_limited" {
				rateLimitedCount++
			}
		}
		if rateLimitedCount > 0 {
			session.sendWSMessage("log", fmt.Sprintf("检测到 %d 个 IP 返回 HTTP 429（速率限制），自动暂停扫描以避免被封禁", rateLimitedCount))
			_, _ = db.Exec(`UPDATE scan_meta SET status = 'paused', updated_at = ? WHERE id = 1`, time.Now().Format(time.RFC3339))
			meta.Status = "paused"
			meta.UpdatedAt = time.Now().Format(time.RFC3339)
			session.sendWSMessage("full_scan_paused", meta.fullScanFileInfo)
			session.sendWSMessage("log", fmt.Sprintf("全库扫描已暂停：%s，已保存 %d/%d，建议稍后降低并发或增加延迟后继续", fileName, meta.Processed, meta.Total))
			sendFullScanFiles(session)
			return
		}

		// 连续高失败率检测：如果连续 3 批全部失败，可能已被封锁
		batchTotal := successes + failures
		if batchTotal > 0 && successes == 0 {
			consecutiveHighFailureBatches++
			if consecutiveHighFailureBatches >= 3 {
				session.sendWSMessage("log", "连续 3 批扫描全部失败，可能已被封锁或网络异常，自动暂停扫描")
				_, _ = db.Exec(`UPDATE scan_meta SET status = 'paused', updated_at = ? WHERE id = 1`, time.Now().Format(time.RFC3339))
				meta.Status = "paused"
				meta.UpdatedAt = time.Now().Format(time.RFC3339)
				session.sendWSMessage("full_scan_paused", meta.fullScanFileInfo)
				session.sendWSMessage("log", fmt.Sprintf("全库扫描已暂停：%s，已保存 %d/%d", fileName, meta.Processed, meta.Total))
				sendFullScanFiles(session)
				return
			}
		} else {
			consecutiveHighFailureBatches = 0
		}

		next = checkpoint
		if checkpoint < end {
			break
		}
		// 批次间冷却，降低持续高频请求被风控的风险
		if fullScanBatchCooldown > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(fullScanBatchCooldown):
			}
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

func scanFullIPv4Batch(ctx context.Context, targets []uint32, indices []int, threads, port, delay int, cache *fullScanSubnetCache) []fullScanRecord {
	if len(indices) == 0 {
		return nil
	}
	if threads <= 0 {
		threads = 100
	}
	if threads > fullScanMaxThreads {
		threads = fullScanMaxThreads
	}
	if threads > len(indices) {
		threads = len(indices)
	}

	// 打乱扫描顺序，避免连续 IP 段被判定为端口扫描
	shuffled := make([]int, len(indices))
	copy(shuffled, indices)
	rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})

	// 全局速率限制器：所有 worker 共享一个 ticker，控制每秒新建连接数
	rateInterval := time.Duration(delay) * time.Millisecond
	if rateInterval < time.Duration(fullScanMinDelay)*time.Millisecond {
		rateInterval = time.Duration(fullScanMinDelay) * time.Millisecond
	}
	rateLimiter := time.NewTicker(rateInterval)
	defer rateLimiter.Stop()

	jobs := make(chan int)
	results := make(chan fullScanRecord, len(shuffled))
	var workers sync.WaitGroup
	for worker := 0; worker < threads; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				// 等待全局速率限制器放行
				select {
				case <-ctx.Done():
					return
				case <-rateLimiter.C:
				}
				// 随机抖动，进一步分散请求，避免同步突发
				if fullScanJitterRange > 0 {
					jitter := time.Duration(rand.Intn(fullScanJitterRange)) * time.Millisecond
					select {
					case <-ctx.Done():
						return
					case <-time.After(jitter):
					}
				}

				if ctx.Err() != nil {
					return
				}
				ipNumber := targets[index]
				ip := uint32ToIPv4(ipNumber)

				// 子网推断：如果同 /24 已有 DC 信息，只做 TCP ping，不发 trace 请求
				if cached, ok := cache.get(ip); ok {
					duration, category, detail := tcpPingIP(ctx, ip, port, delay)
					if ctx.Err() != nil {
						return
					}
					record := fullScanRecord{TargetIndex: index, IP: ip, IPNumber: ipNumber, FailureCategory: category, FailureDetail: detail}
					if len(record.FailureDetail) > 1000 {
						record.FailureDetail = record.FailureDetail[:1000]
					}
					if category == "" {
						record.Success = true
						record.DataCenter = cached.DataCenter
						record.DCCountry = cached.DCCountry
						record.Region = cached.Region
						record.City = cached.City
						record.LatencyMS = duration.Milliseconds()
					}
					results <- record
				} else {
					// 首次扫描该子网：完整 TCP + trace 请求
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
						// 缓存 DC 信息，同子网后续 IP 不再发 trace
						cache.set(ip, result)
					}
					results <- record
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, index := range shuffled {
			select {
			case <-ctx.Done():
				return
			case jobs <- index:
			}
		}
	}()
	workers.Wait()
	close(results)
	records := make([]fullScanRecord, 0, len(shuffled))
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
