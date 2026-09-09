package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestBuildFullIPv4Targets(t *testing.T) {
	targets, sourceCount, err := buildFullIPv4Targets("192.0.2.0/30\n192.0.2.1\n")
	if err != nil {
		t.Fatal(err)
	}
	if sourceCount != 2 {
		t.Fatalf("source count = %d, want 2", sourceCount)
	}
	if len(targets) != 2 {
		t.Fatalf("target count = %d, want 2", len(targets))
	}
	if got := uint32ToIPv4(targets[0]); got != "192.0.2.1" {
		t.Fatalf("first target = %s, want 192.0.2.1", got)
	}
	if got := uint32ToIPv4(targets[1]); got != "192.0.2.2" {
		t.Fatalf("second target = %s, want 192.0.2.2", got)
	}
}

func TestPersistFullScanBatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.db")
	db, err := openFullScanDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now()
	if err := initFullScanDB(db, "scan.db", "192.0.2.0/30", 1, 2, 10, 443, 500, now); err != nil {
		t.Fatal(err)
	}
	records := []fullScanRecord{
		{TargetIndex: 0, IP: "192.0.2.1", IPNumber: 3221225985, Success: true, DataCenter: "NRT", DCCountry: "JP", City: "Tokyo", LatencyMS: 50},
		{TargetIndex: 1, IP: "192.0.2.2", IPNumber: 3221225986, FailureCategory: "tcp_connect_failed", FailureDetail: "timeout"},
	}
	inserted, successes, failures, err := persistFullScanBatch(db, records, 2)
	if err != nil {
		t.Fatal(err)
	}
	if inserted != 2 || successes != 1 || failures != 1 {
		t.Fatalf("persist counts = %d/%d/%d, want 2/1/1", inserted, successes, failures)
	}
	meta, err := loadFullScanMeta(db)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Processed != 2 || meta.Success != 1 || meta.Failed != 1 || meta.NextIndex != 2 {
		t.Fatalf("meta counts = processed:%d success:%d failed:%d next:%d", meta.Processed, meta.Success, meta.Failed, meta.NextIndex)
	}
}
