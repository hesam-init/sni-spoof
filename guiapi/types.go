// Package guiapi holds config and result types shared by the Wails GUI and
// the privileged helper process.
package guiapi

type ProxyConfig struct {
	Listen          string `json:"listen"`
	Connect         string `json:"connect"`
	FakeSNI         string `json:"fakeSni"`
	UTLS            string `json:"utls"`
	Injector        string `json:"injector"`
	FakeRepeat      int    `json:"fakeRepeat"`
	FakeDelayMs     int    `json:"fakeDelayMs"`
	AckTimeoutMs    int    `json:"ackTimeoutMs"`
	EnableFragment  bool   `json:"enableFragment"`
	FragmentDelayMs int    `json:"fragmentDelayMs"`
	SNIChunk        int    `json:"sniChunk"`
}

type ProxyStatus struct {
	Running    bool   `json:"running"`
	Testing    bool   `json:"testing"`
	ListenAddr string `json:"listenAddr"`
}

type LogEvent struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}

type TestResult struct {
	UTLS           string `json:"utls"`
	FakeRepeat     int    `json:"fakeRepeat"`
	EnableFragment bool   `json:"enableFragment"`
	Pass           bool   `json:"pass"`
	Error          string `json:"error,omitempty"`
}

type TestSummary struct {
	Preflight TestPreflight `json:"preflight"`
	Results   []TestResult  `json:"results"`
	Passed    int           `json:"passed"`
	Failed    int           `json:"failed"`
}

type TestPreflight struct {
	ExternalIP string `json:"externalIp"`
	InternalIP string `json:"internalIp"`
	Matched    bool   `json:"matched"`
	Warning    string `json:"warning,omitempty"`
}

func DefaultConfig(injector string) ProxyConfig {
	return ProxyConfig{
		Listen:          "127.0.0.1:40443",
		Connect:         "104.19.229.21:443",
		FakeSNI:         "hcaptcha.com",
		UTLS:            "firefox",
		Injector:        injector,
		FakeRepeat:      1,
		FakeDelayMs:     2,
		AckTimeoutMs:    2000,
		EnableFragment:  false,
		FragmentDelayMs: 500,
		SNIChunk:        3,
	}
}
