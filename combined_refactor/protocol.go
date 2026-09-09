package main

import "encoding/json"

type wsRequest struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

type startTaskRequest struct {
	IPType             int     `json:"ipType"`
	Threads            int     `json:"threads"`
	Port               int     `json:"port"`
	Delay              int     `json:"delay"`
	ScanMode           string  `json:"scanMode"`
	AutoSpeed          bool    `json:"autoSpeed"`
	OfficialTargetDC   string  `json:"officialTargetDC"`
	OfficialSpeedPort  int     `json:"officialSpeedPort"`
	OfficialSpeedURL   string  `json:"officialSpeedURL"`
	OfficialSpeedMin   float64 `json:"officialSpeedMin"`
	OfficialSpeedLimit int     `json:"officialSpeedLimit"`
	EdgeTestEnabled    bool    `json:"edgeTestEnabled"`
	EdgeTestHost       string  `json:"edgeTestHost"`
	EdgeTestPort       int     `json:"edgeTestPort"`
	EdgeTestProtocol   string  `json:"edgeTestProtocol"`
	EdgeTestUUID       string  `json:"edgeTestUUID"`
	EdgeTestPath       string  `json:"edgeTestPath"`
	EdgeTestTargetURL  string  `json:"edgeTestTargetURL"`
}

type startTestRequest struct {
	DC                string `json:"dc"`
	Port              int    `json:"port"`
	Delay             int    `json:"delay"`
	ScanMode          string `json:"scanMode"`
	EdgeTestEnabled   bool   `json:"edgeTestEnabled"`
	EdgeTestHost      string `json:"edgeTestHost"`
	EdgeTestPort      int    `json:"edgeTestPort"`
	EdgeTestProtocol  string `json:"edgeTestProtocol"`
	EdgeTestUUID      string `json:"edgeTestUUID"`
	EdgeTestPath      string `json:"edgeTestPath"`
	EdgeTestTargetURL string `json:"edgeTestTargetURL"`
}

type startSpeedTestRequest struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
	URL  string `json:"url"`
}

type startEdgeTestRequest struct {
	IP        string `json:"ip"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	UUID      string `json:"uuid"`
	Path      string `json:"path"`
	TargetURL string `json:"targetURL"`
}

type startFullScanRequest struct {
	Threads int `json:"threads"`
	Port    int `json:"port"`
	Delay   int `json:"delay"`
}

type fullScanFileRequest struct {
	FileName string `json:"fileName"`
}

type startFullScanEdgeTestRequest struct {
	FileName  string `json:"fileName"`
	DC        string `json:"dc"`
	Limit     int    `json:"limit"`
	Delay     int    `json:"delay"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	UUID      string `json:"uuid"`
	Path      string `json:"path"`
	TargetURL string `json:"targetURL"`
}

type startOfficialSpeedBatchRequest struct {
	Port       int          `json:"port"`
	URL        string       `json:"url"`
	SpeedMin   float64      `json:"speedMin"`
	SpeedLimit int          `json:"speedLimit"`
	Results    []TestResult `json:"results"`
	SkipTested bool         `json:"skipTested"`
}

type startNSBTaskRequest struct {
	FileName     string  `json:"fileName"`
	FileContent  string  `json:"fileContent"`
	SourceURL    string  `json:"sourceURL"`
	OutFile      string  `json:"outFile"`
	MaxThreads   int     `json:"maxThreads"`
	FallbackPort int     `json:"fallbackPort"`
	SpeedTest    int     `json:"speedTest"`
	SpeedURL     string  `json:"speedURL"`
	EnableTLS    bool    `json:"enableTLS"`
	Delay        int     `json:"delay"`
	ResultLimit  int     `json:"resultLimit"`
	DC           string  `json:"dc"`
	SpeedMin     float64 `json:"speedMin"`
	SpeedLimit   int     `json:"speedLimit"`
	Compact      bool    `json:"compact"`
	ScanMode     string  `json:"scanMode"`
}

type startNSBSpeedBatchRequest struct {
	Results    []nsbScanMessage `json:"results"`
	SpeedTest  int              `json:"speedTest"`
	SpeedURL   string           `json:"speedURL"`
	EnableTLS  bool             `json:"enableTLS"`
	SpeedMin   float64          `json:"speedMin"`
	SpeedLimit int              `json:"speedLimit"`
	SkipTested bool             `json:"skipTested"`
	Compact    bool             `json:"compact"`
}

type githubUploadRequest struct {
	Token   string `json:"token"`
	Owner   string `json:"owner"`
	Repo    string `json:"repo"`
	Branch  string `json:"branch"`
	Path    string `json:"path"`
	Message string `json:"message"`
	Content string `json:"content"`
	Silent  bool   `json:"silent"`
}
