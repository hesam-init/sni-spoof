package main

import (
	"strings"
	"testing"

	"sni-spoofing-go/guiapi"
)

func validConfig() ProxyConfig {
	return ProxyConfig{
		Listen:          "127.0.0.1:40443",
		Connect:         "1.1.1.1:443",
		FakeSNI:         "hcaptcha.com",
		UTLS:            "firefox",
		Injector:        "active",
		FakeRepeat:      1,
		FakeDelayMs:     2,
		AckTimeoutMs:    2000,
		EnableFragment:  false,
		FragmentDelayMs: 500,
		SNIChunk:        3,
	}
}

func TestValidateConfig_AcceptsDefault(t *testing.T) {
	if err := guiapi.ValidateConfig(validConfig()); err != nil {
		t.Fatalf("expected default config to pass, got: %v", err)
	}
}

func TestValidateConfig_Rejects(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(c *ProxyConfig)
		wantInMsg string
	}{
		{"blank listen", func(c *ProxyConfig) { c.Listen = "   " }, "listen"},
		{"blank connect", func(c *ProxyConfig) { c.Connect = "" }, "connect"},
		{"fake-repeat zero", func(c *ProxyConfig) { c.FakeRepeat = 0 }, "fake-repeat"},
		{"fake-repeat negative", func(c *ProxyConfig) { c.FakeRepeat = -1 }, "fake-repeat"},
		{"fake-repeat too large", func(c *ProxyConfig) { c.FakeRepeat = guiapi.MaxFakeRepeat + 1 }, "fake-repeat"},
		{"sni-chunk negative", func(c *ProxyConfig) { c.SNIChunk = -1 }, "sni-chunk"},
		{"sni-chunk too large", func(c *ProxyConfig) { c.SNIChunk = guiapi.MaxSNIChunk + 1 }, "sni-chunk"},
		{"ack-timeout zero", func(c *ProxyConfig) { c.AckTimeoutMs = 0 }, "ack-timeout"},
		{"ack-timeout negative", func(c *ProxyConfig) { c.AckTimeoutMs = -1 }, "ack-timeout"},
		{"ack-timeout too large", func(c *ProxyConfig) { c.AckTimeoutMs = guiapi.MaxAckTimeoutMs + 1 }, "ack-timeout"},
		{"fake-delay negative", func(c *ProxyConfig) { c.FakeDelayMs = -1 }, "fake-delay"},
		{"fake-delay too large", func(c *ProxyConfig) { c.FakeDelayMs = guiapi.MaxFakeDelayMs + 1 }, "fake-delay"},
		{"fragment-delay negative", func(c *ProxyConfig) { c.FragmentDelayMs = -1 }, "fragment-delay"},
		{"fragment-delay too large", func(c *ProxyConfig) { c.FragmentDelayMs = guiapi.MaxFragmentDelayMs + 1 }, "fragment-delay"},
		{"injector blank", func(c *ProxyConfig) { c.Injector = "" }, "injector"},
		{"injector unknown", func(c *ProxyConfig) { c.Injector = "nfqueue" }, "injector"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)
			err := guiapi.ValidateConfig(cfg)
			if err == nil {
				t.Fatalf("ValidateConfig accepted invalid config %+v", cfg)
			}
			if !strings.Contains(err.Error(), tc.wantInMsg) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.wantInMsg)
			}
		})
	}
}

func TestValidateConfig_AcceptsBoundaryValues(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(c *ProxyConfig)
	}{
		{"sni-chunk 0", func(c *ProxyConfig) { c.SNIChunk = 0 }},
		{"sni-chunk at max", func(c *ProxyConfig) { c.SNIChunk = guiapi.MaxSNIChunk }},
		{"fake-delay 0", func(c *ProxyConfig) { c.FakeDelayMs = 0 }},
		{"fake-delay at max", func(c *ProxyConfig) { c.FakeDelayMs = guiapi.MaxFakeDelayMs }},
		{"fragment-delay 0", func(c *ProxyConfig) { c.FragmentDelayMs = 0 }},
		{"fragment-delay at max", func(c *ProxyConfig) { c.FragmentDelayMs = guiapi.MaxFragmentDelayMs }},
		{"fake-repeat 1", func(c *ProxyConfig) { c.FakeRepeat = 1 }},
		{"fake-repeat at max", func(c *ProxyConfig) { c.FakeRepeat = guiapi.MaxFakeRepeat }},
		{"ack-timeout 1", func(c *ProxyConfig) { c.AckTimeoutMs = 1 }},
		{"ack-timeout at max", func(c *ProxyConfig) { c.AckTimeoutMs = guiapi.MaxAckTimeoutMs }},
		{"injector passive", func(c *ProxyConfig) { c.Injector = "passive" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)
			if err := guiapi.ValidateConfig(cfg); err != nil {
				t.Fatalf("expected boundary value to pass, got: %v", err)
			}
		})
	}
}

func TestBuildProxyArgs_RejectsBadInput(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(c *ProxyConfig)
		wantInMsg string
	}{
		{
			name:      "unknown uTLS preset",
			mutate:    func(c *ProxyConfig) { c.UTLS = "netscape_navigator" },
			wantInMsg: "utls",
		},
		{
			name:      "IPv6 listen host",
			mutate:    func(c *ProxyConfig) { c.Listen = "[::1]:40443" },
			wantInMsg: "listen",
		},
		{
			name:      "connect missing port",
			mutate:    func(c *ProxyConfig) { c.Connect = "example.com" },
			wantInMsg: "configuration",
		},
		{
			name:      "listen missing port",
			mutate:    func(c *ProxyConfig) { c.Listen = "127.0.0.1" },
			wantInMsg: "configuration",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)
			_, _, err := guiapi.BuildProxyArgs(cfg, false)
			if err == nil {
				t.Fatalf("BuildProxyArgs accepted invalid config %+v", cfg)
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.wantInMsg) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.wantInMsg)
			}
		})
	}
}

func TestBuildProxyArgs_AcceptsLegacyUTLSAndPortZero(t *testing.T) {
	cfg := validConfig()
	cfg.UTLS = "none"
	cfg.Listen = "127.0.0.1:0"
	pc, opts, err := guiapi.BuildProxyArgs(cfg, true)
	if err != nil {
		t.Fatalf("expected legacy uTLS + port:0 to pass, got: %v", err)
	}
	if pc == nil {
		t.Fatal("BuildProxyArgs returned nil config without error")
	}
	if opts.Injector == "" {
		t.Fatal("Options.Injector not populated")
	}
}

func TestStop_NoopWhenIdle(t *testing.T) {
	a := NewApp()
	if err := a.Stop(); err != nil {
		t.Fatalf("Stop on idle App returned: %v", err)
	}
	st := a.Status()
	if st.Running || st.Testing {
		t.Fatalf("Status after idle Stop = %+v, want all-false", st)
	}
}
