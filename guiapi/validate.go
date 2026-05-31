package guiapi

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"sni-spoofing-go/config"
	"sni-spoofing-go/network"
	"sni-spoofing-go/packet"
	"sni-spoofing-go/proxy"
)

const (
	MaxFakeRepeat      = 20
	MaxFakeDelayMs     = 10_000
	MaxAckTimeoutMs    = 60_000
	MaxFragmentDelayMs = 60_000
	MaxSNIChunk        = 256
)

func ValidateConfig(cfg ProxyConfig) error {
	if strings.TrimSpace(cfg.Listen) == "" {
		return errors.New("listen address is required")
	}
	if strings.TrimSpace(cfg.Connect) == "" {
		return errors.New("connect address is required")
	}
	if cfg.FakeRepeat < 1 {
		return errors.New("fake-repeat must be at least 1")
	}
	if cfg.FakeRepeat > MaxFakeRepeat {
		return fmt.Errorf("fake-repeat must be <= %d", MaxFakeRepeat)
	}
	if cfg.SNIChunk < 0 {
		return errors.New("sni-chunk must be >= 0 (0 = whole hostname in one write)")
	}
	if cfg.SNIChunk > MaxSNIChunk {
		return fmt.Errorf("sni-chunk must be <= %d bytes", MaxSNIChunk)
	}
	if cfg.AckTimeoutMs <= 0 {
		return fmt.Errorf("ack-timeout must be positive (got %dms)", cfg.AckTimeoutMs)
	}
	if cfg.AckTimeoutMs > MaxAckTimeoutMs {
		return fmt.Errorf("ack-timeout must be <= %dms", MaxAckTimeoutMs)
	}
	if cfg.FakeDelayMs < 0 {
		return errors.New("fake-delay must be >= 0")
	}
	if cfg.FakeDelayMs > MaxFakeDelayMs {
		return fmt.Errorf("fake-delay must be <= %dms", MaxFakeDelayMs)
	}
	if cfg.FragmentDelayMs < 0 {
		return errors.New("fragment-delay must be >= 0")
	}
	if cfg.FragmentDelayMs > MaxFragmentDelayMs {
		return fmt.Errorf("fragment-delay must be <= %dms", MaxFragmentDelayMs)
	}
	switch cfg.Injector {
	case "active", "passive":
	default:
		return fmt.Errorf("injector must be 'active' or 'passive', got %q", cfg.Injector)
	}
	return nil
}

func BuildProxyArgs(cfg ProxyConfig, allowPortZero bool) (*config.Config, proxy.Options, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, proxy.Options{}, err
	}
	injector, err := proxy.ParseInjectorMode(cfg.Injector)
	if err != nil {
		return nil, proxy.Options{}, err
	}
	fakeSNI := strings.TrimSpace(cfg.FakeSNI)
	var pc *config.Config
	if allowPortZero {
		pc, err = config.ConnectFromCLIAllowListenPortZero(cfg.Listen, cfg.Connect, fakeSNI)
	} else {
		pc, err = config.ConnectFromCLI(cfg.Listen, cfg.Connect, fakeSNI)
	}
	if err != nil {
		return nil, proxy.Options{}, fmt.Errorf("invalid configuration: %w", err)
	}
	if strings.TrimSpace(cfg.UTLS) != "" {
		pc.UTLSClientHello = cfg.UTLS
	}
	if !packet.IsLegacyUTLS(pc.UTLSClientHello) {
		if _, err := packet.ParseClientHelloID(pc.UTLSClientHello); err != nil {
			return nil, proxy.Options{}, fmt.Errorf("invalid -utls: %w", err)
		}
	}
	if !network.IsIPv4(pc.ConnectIP) {
		return nil, proxy.Options{}, fmt.Errorf("upstream must resolve to IPv4 (IPv6 is not supported): %q", pc.ConnectIP)
	}
	if len(pc.ConnectIPv4s) == 0 {
		return nil, proxy.Options{}, errors.New("internal error: no ConnectIPv4s after resolve")
	}
	if pc.ListenHost != "" && !network.IsIPv4(pc.ListenHost) {
		return nil, proxy.Options{}, fmt.Errorf("listen host must be IPv4 or empty: %q", pc.ListenHost)
	}
	opts := proxy.Options{
		FakeRepeat:     cfg.FakeRepeat,
		FakeDelay:      time.Duration(cfg.FakeDelayMs) * time.Millisecond,
		EnableFragment: cfg.EnableFragment,
		FragmentDelay:  time.Duration(cfg.FragmentDelayMs) * time.Millisecond,
		SNIChunk:       cfg.SNIChunk,
		AckTimeout:     time.Duration(cfg.AckTimeoutMs) * time.Millisecond,
		Injector:       injector,
	}
	return pc, opts, nil
}
