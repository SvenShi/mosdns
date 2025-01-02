/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package ospf

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
	"github.com/IrineSistiana/mosdns/v5/pkg/ospf_cnn"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/go-chi/chi/v5"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"
)

const PluginType = "ospf"

func init() {
	// Register this plugin type with its initialization funcs. So that, this plugin
	// can be configured by user from configuration file.
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })

	// You can register a quick setup func for sequence. So that users can
	// init your plugin in the sequence directly in one string.
	sequence.MustRegExecQuickSetup(PluginType, QuickSetup)
}

type PersistentRouteConfig struct {
	Files []string `yaml:"files"`
	IPs   []string `yaml:"ips"`
}

type CallConfig struct {
	Url    string            `yaml:"url"`
	Method string            `yaml:"method"`
	Body   string            `yaml:"body"`
	Heads  map[string]string `yaml:"heads"`
}

// Args is the arguments of plugin. It will be decoded from yaml.
// So it is recommended to use `yaml` as struct field's tag.
type Args struct {
	Ttl             uint                  `yaml:"ttl"`
	Iface           string                `yaml:"iface"`
	Ip              string                `yaml:"ip"`
	RouterId        string                `yaml:"routerId"`
	PersistentRoute PersistentRouteConfig `yaml:"persistentRoute"`
	Calls           []CallConfig          `yaml:"init-calls"`
}

var _ sequence.Executable = (*OSPF)(nil)

// OSPF implements handler.ExecutablePlugin.
type OSPF struct {
	logger   *zap.Logger
	router   *ospf_cnn.Router
	ipPool   *IpPool
	routerId uint
}

var MaskV4 = net.IPv4Mask(255, 255, 255, 255)

// Exec implements handler.Executable.
func (o *OSPF) Exec(_ context.Context, qCtx *query_context.Context) error {
	r := qCtx.R()
	if r == nil {
		return nil
	}

	// 使用 map[string][]net.IPNet 来存储结果
	var ips = make(map[string][]net.IPNet)

	for _, rr := range r.Answer {
		nets := ips[rr.Header().Name]

		switch rr := rr.(type) {
		case *dns.A:
			nets = append(nets, net.IPNet{IP: rr.A, Mask: MaskV4})
			ips[rr.Header().Name] = nets
		case *dns.AAAA:
			continue
		default:
			continue
		}
	}

	if len(ips) > 0 {
		for s, nets := range ips {
			if o.logger.Level() == zapcore.DebugLevel {
				for _, ip := range nets {
					o.logger.Debug("add route ", zap.String("domain", s), zap.String("ip", ip.String()))
				}
			}
			o.router.AnnounceASBRRoute(nets)
			go o.ipPool.AddIps(s, nets)
		}
	}

	return nil
}

func (o *OSPF) Close() error {
	return o.router.Close()
}

func Init(b *coremain.BP, args any) (any, error) {
	arg := args.(*Args)
	var allCIDRs []net.IPNet
	allCIDRs, err := LoadFromIPsAndFiles(arg.PersistentRoute.IPs, arg.PersistentRoute.Files, allCIDRs)
	if err != nil {
		return nil, err
	}
	p, err := parseNetipPrefix(arg.Ip)
	if err != nil {
		return nil, err
	}

	ipNet := net.IPNet{
		IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), 32),
	}
	ospf_cnn.SetLogger(b.L())

	router, err := ospf_cnn.NewRouter(arg.Iface, &ipNet, p.Addr().String(), arg.RouterId)
	if err != nil {
		return nil, err
	}
	router.Start()
	if len(allCIDRs) > 0 {
		if b.L().Level() == zapcore.DebugLevel {
			for _, ip := range allCIDRs {
				b.L().Debug("add persistent route", zap.String("ip", ip.String()))
			}
		}
		router.AnnounceASBRRoute(allCIDRs)
	}

	ipPool := NewIpPool(arg.Ttl, router, b.L())
	ipPool.Init()

	o := &OSPF{
		logger: b.L(), router: router, ipPool: ipPool,
	}

	b.RegAPI(o.Api())

	callApi(arg.Calls, b.L())

	b.L().Info("init success")

	return o, nil
}

func (o *OSPF) Api() *chi.Mux {
	r := chi.NewRouter()
	r.Get("/alive", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return r
}

func callApi(calls []CallConfig, logger *zap.Logger) {
	// 使用 goroutines 来异步调用每个 API 配置
	for _, call := range calls {
		go func(call CallConfig) {
			// 构建请求的 URL 和请求头
			req, err := http.NewRequest(call.Method, call.Url, strings.NewReader(call.Body))
			if err != nil {
				// 记录错误信息
				logger.Error("failed to create request", zap.String("url", call.Url), zap.Error(err))
				return
			}

			// 设置请求头
			for key, value := range call.Heads {
				req.Header.Set(key, value)
			}

			// 执行请求
			client := &http.Client{Timeout: 30 * time.Second} // 设置超时为30秒
			resp, err := client.Do(req)
			if err != nil {
				// 请求失败，记录错误信息
				logger.Error("failed to execute request", zap.String("url", call.Url), zap.Error(err))
				return
			}
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {
					logger.Error("failed to close body stream", zap.String("url", call.Url), zap.Error(err))
				}
			}(resp.Body)

			// 读取响应内容
			respBody := new(bytes.Buffer)
			_, err = respBody.ReadFrom(resp.Body)
			if err != nil {
				// 读取响应失败
				logger.Error("failed to read response body", zap.String("url", call.Url), zap.Error(err))
				return
			}

			// 记录响应内容
			logger.Info("API call completed", zap.String("url", call.Url), zap.Int("status", resp.StatusCode), zap.String("response", respBody.String()))
		}(call)
	}
}

func QuickSetup(_ sequence.BQ, s string) (any, error) {
	return &OSPF{}, nil
}

func parseNetipPrefix(s string) (netip.Prefix, error) {
	if strings.ContainsRune(s, '/') {
		return netip.ParsePrefix(s)
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return addr.Prefix(addr.BitLen())
}

func LoadFromIPsAndFiles(ips []string, fs []string, l []net.IPNet) ([]net.IPNet, error) {
	l, err := LoadFromIPs(ips, l)
	if err != nil {
		return l, err
	}
	l, err = LoadFromFiles(fs, l)
	if err != nil {
		return l, err
	}
	return l, nil
}

func LoadFromIPs(ips []string, l []net.IPNet) ([]net.IPNet, error) {
	for i, s := range ips {
		p, err := parseNetipPrefix(s)
		if err != nil {
			return l, fmt.Errorf("invalid ip #%d %s, %w", i, s, err)
		}
		if p.Addr().Is4() {
			l = append(l, net.IPNet{
				IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), 32),
			})
		}
	}
	return l, nil
}

func LoadFromFiles(fs []string, l []net.IPNet) ([]net.IPNet, error) {
	for i, f := range fs {
		tmpl, err := LoadFromFile(f, l)
		if err != nil {
			return tmpl, fmt.Errorf("failed to load file #%d %s, %w", i, f, err)
		}
		l = append(l, tmpl...)
	}
	return l, nil
}

func LoadFromFile(f string, l []net.IPNet) ([]net.IPNet, error) {
	if len(f) > 0 {
		b, err := os.ReadFile(f)
		if err != nil {
			return l, err
		}
		l, err = LoadFromReader(l, bytes.NewReader(b))
		if err != nil {
			return l, err
		}
	}
	return l, nil
}

type MatcherGroup []netlist.Matcher

func (mg MatcherGroup) Match(addr netip.Addr) bool {
	for _, m := range mg {
		if m.Match(addr) {
			return true
		}
	}
	return false
}

func LoadFromReader(l []net.IPNet, reader io.Reader) ([]net.IPNet, error) {
	scanner := bufio.NewScanner(reader)

	// count how many lines we have read.
	lineCounter := 0
	for scanner.Scan() {
		lineCounter++
		s := scanner.Text()
		s = strings.TrimSpace(s)
		s = utils.RemoveComment(s, "#")
		s = utils.RemoveComment(s, " ")
		if len(s) == 0 {
			continue
		}
		ips, err := LoadFromText(l, s)
		if err != nil {
			return l, fmt.Errorf("invalid data at line #%d: %w", lineCounter, err)
		}
		l = ips
	}
	return l, scanner.Err()
}

// LoadFromText loads an IP from s.
// It might modify the List and causes List unsorted.
func LoadFromText(l []net.IPNet, s string) ([]net.IPNet, error) {
	if strings.ContainsRune(s, '/') {
		ipNet, err := netip.ParsePrefix(s)
		if err != nil {
			return l, err
		}
		if ipNet.Addr().Is4() {
			l = append(l, net.IPNet{
				IP: ipNet.Addr().AsSlice(), Mask: net.CIDRMask(ipNet.Bits(), 32),
			})
		}
		return l, nil
	}

	addr, err := netip.ParseAddr(s)
	if err != nil {
		return l, err
	}
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	from := netip.PrefixFrom(addr, bits)
	l = append(l, net.IPNet{
		IP: from.Addr().AsSlice(), Mask: net.CIDRMask(from.Bits(), 32),
	})
	return l, nil
}
