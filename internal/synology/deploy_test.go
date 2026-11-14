package synology

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/synologyer/allinssl_plugins/internal/certutil"
	"github.com/synologyer/allinssl_plugins/internal/testcert"
)

// fakeDSM 模拟群晖 Web API 中本插件用到的接口。
type fakeDSM struct {
	t        *testing.T
	mu       sync.Mutex
	password string
	certs    []map[string]any // 设备上已有的证书
	imports  []map[string]string
	logouts  int
}

func (f *fakeDSM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path != "/webapi/entry.cgi" {
		http.NotFound(w, r)
		return
	}
	query := r.URL.Query()
	reply := func(value any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(value)
	}
	fail := func(code int) {
		reply(map[string]any{"success": false, "error": map[string]any{"code": code}})
	}
	api, method := query.Get("api"), query.Get("method")
	if api != "SYNO.API.Auth" && r.Header.Get("X-SYNO-TOKEN") != "token-1" {
		fail(119)
		return
	}
	switch api + "." + method {
	case "SYNO.API.Auth.login":
		if query.Get("passwd") != f.password {
			fail(400)
			return
		}
		reply(map[string]any{"success": true, "data": map[string]any{"sid": "sid-1", "synotoken": "token-1"}})
	case "SYNO.API.Auth.logout":
		if query.Get("_sid") != "sid-1" {
			fail(119)
			return
		}
		f.logouts++
		reply(map[string]any{"success": true})
	case "SYNO.Core.Certificate.CRT.list":
		reply(map[string]any{"success": true, "data": map[string]any{"certificates": f.certs}})
	case "SYNO.Core.Certificate.import":
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			f.t.Errorf("导入请求不是合法的 multipart 表单: %v", err)
			fail(100)
			return
		}
		fields := map[string]string{}
		for key, values := range r.MultipartForm.Value {
			fields[key] = values[0]
		}
		for key, files := range r.MultipartForm.File {
			file, err := files[0].Open()
			if err != nil {
				f.t.Errorf("读取上传文件 %s 失败: %v", key, err)
				continue
			}
			var content strings.Builder
			buffer := make([]byte, 4096)
			for {
				n, readErr := file.Read(buffer)
				content.Write(buffer[:n])
				if readErr != nil {
					break
				}
			}
			file.Close()
			fields["file:"+key] = content.String()
		}
		f.imports = append(f.imports, fields)
		reply(map[string]any{"success": true, "data": map[string]any{"id": "new-id"}})
	default:
		fail(102)
	}
}

func newFakeDSM(t *testing.T) (*fakeDSM, Config) {
	t.Helper()
	fake := &fakeDSM{t: t, password: "secret"}
	server := httptest.NewTLSServer(fake)
	t.Cleanup(server.Close)
	return fake, Config{URL: server.URL, Username: "admin", Password: "secret", SkipVerify: true}
}

func newBundle(t *testing.T, dnsNames ...string) *certutil.CertBundle {
	t.Helper()
	certPEM, keyPEM, err := testcert.Valid(dnsNames...)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := certutil.ParseCertBundle([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func TestDeployUploadsNewCertificate(t *testing.T) {
	fake, cfg := newFakeDSM(t)
	cfg.AsDefault = true
	bundle := newBundle(t, "nas.example.com", "*.example.com")

	existed, err := Deploy(context.Background(), cfg, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if existed {
		t.Fatal("新证书不应被判定为已存在")
	}
	if len(fake.imports) != 1 {
		t.Fatalf("应导入 1 次，实际 %d 次", len(fake.imports))
	}
	got := fake.imports[0]
	if got["desc"] != bundle.GetNoteShort() || got["as_default"] != "true" {
		t.Errorf("表单字段不正确: desc=%q as_default=%q", got["desc"], got["as_default"])
	}
	if _, hasID := got["id"]; hasID {
		t.Error("新证书不应携带 id")
	}
	if got["file:cert"] != bundle.Certificate || got["file:key"] != bundle.PrivateKey {
		t.Error("上传的证书或私钥内容不正确")
	}
	if fake.logouts != 1 {
		t.Errorf("应登出 1 次，实际 %d 次", fake.logouts)
	}
}

func TestDeploySkipsExistingCertificate(t *testing.T) {
	fake, cfg := newFakeDSM(t)
	bundle := newBundle(t, "nas.example.com")
	fake.certs = []map[string]any{
		{"id": "other", "desc": "手动上传", "subject": map[string]any{"sub_alt_name": []string{"nas.example.com"}}, "valid_till": "Jan  5 12:00:00 2099 GMT"},
		{"id": "abc", "desc": bundle.GetNoteShort(), "subject": map[string]any{"sub_alt_name": []string{"nas.example.com"}}, "valid_till": "Jan  5 12:00:00 2099 GMT"},
	}

	existed, err := Deploy(context.Background(), cfg, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !existed || len(fake.imports) != 0 {
		t.Fatalf("已存在且未过期的证书不应重复上传: existed=%v imports=%d", existed, len(fake.imports))
	}
	if fake.logouts != 1 {
		t.Errorf("应登出 1 次，实际 %d 次", fake.logouts)
	}
}

func TestDeployReplacesExpiredRecord(t *testing.T) {
	fake, cfg := newFakeDSM(t)
	bundle := newBundle(t, "nas.example.com")
	fake.certs = []map[string]any{
		{"id": "abc", "desc": bundle.GetNoteShort(), "subject": map[string]any{"sub_alt_name": []string{"nas.example.com"}}, "valid_till": "Jan 05 12:00:00 2020 GMT"},
	}

	existed, err := Deploy(context.Background(), cfg, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if existed || len(fake.imports) != 1 || fake.imports[0]["id"] != "abc" {
		t.Fatalf("过期记录应按 id 覆盖: existed=%v imports=%v", existed, fake.imports)
	}
	if fake.imports[0]["as_default"] != "false" {
		t.Errorf("as_default 应为 false，实际 %q", fake.imports[0]["as_default"])
	}
}

func TestDeployLoginFailure(t *testing.T) {
	fake, cfg := newFakeDSM(t)
	cfg.Password = "wrong"

	_, err := Deploy(context.Background(), cfg, newBundle(t, "nas.example.com"))
	if err == nil || !strings.Contains(err.Error(), "登录失败") || !strings.Contains(err.Error(), "400") {
		t.Fatalf("应返回带错误码的登录失败，实际: %v", err)
	}
	if len(fake.imports) != 0 || fake.logouts != 0 {
		t.Error("登录失败后不应继续请求")
	}
}

func TestDeployVerifiesDeviceCertificateWhenAsked(t *testing.T) {
	_, cfg := newFakeDSM(t)
	cfg.SkipVerify = false

	if _, err := Deploy(context.Background(), cfg, newBundle(t, "nas.example.com")); err == nil {
		t.Fatal("关闭跳过校验后，自签名设备证书应导致失败")
	}
}

func TestDeployRejectsExpiredCertificate(t *testing.T) {
	_, cfg := newFakeDSM(t)
	now := time.Now()
	certPEM, keyPEM, err := testcert.Generate(now.Add(-48*time.Hour), now.Add(-24*time.Hour), "nas.example.com")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := certutil.ParseCertBundle([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Deploy(context.Background(), cfg, bundle); err == nil || !strings.Contains(err.Error(), "有效期") {
		t.Fatalf("过期证书应被拒绝，实际: %v", err)
	}
}

func TestValidTillLayout(t *testing.T) {
	for _, value := range []string{"Jan  5 12:00:00 2027 GMT", "Jan 05 12:00:00 2027 GMT", "Dec 15 12:00:00 2027 GMT"} {
		if _, err := time.Parse(validTillLayout, value); err != nil {
			t.Errorf("无法解析 %q: %v", value, err)
		}
	}
}

func TestEnsureAPIPath(t *testing.T) {
	cases := map[string]string{
		"https://nas.example.com:5001":                  "https://nas.example.com:5001/webapi/entry.cgi",
		"https://nas.example.com:5001/":                 "https://nas.example.com:5001/webapi/entry.cgi",
		" http://192.168.1.2:5000 ":                     "http://192.168.1.2:5000/webapi/entry.cgi",
		"https://nas.example.com:5001/webapi/entry.cgi": "https://nas.example.com:5001/webapi/entry.cgi",
		"https://example.com/dsm":                       "https://example.com/dsm/webapi/entry.cgi",
	}
	for input, want := range cases {
		got, err := ensureAPIPath(input)
		if err != nil || got != want {
			t.Errorf("ensureAPIPath(%q) = %q, %v；期望 %q", input, got, err, want)
		}
	}
	for _, input := range []string{"", "nas.example.com:5001", "192.168.1.2", "ftp://nas.example.com"} {
		if _, err := ensureAPIPath(input); err == nil {
			t.Errorf("ensureAPIPath(%q) 应返回错误", input)
		}
	}
}
