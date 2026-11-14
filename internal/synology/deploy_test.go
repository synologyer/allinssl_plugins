package synology

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/synologyer/allinssl_plugins/internal/certutil"
	"github.com/synologyer/allinssl_plugins/internal/testcert"
)

// fakeCert 是模拟设备上的一条证书记录。
type fakeCert struct {
	ID        string
	Desc      string
	IsDefault bool
	SAN       []string
	ValidTill string
}

// fakeDSM 模拟群晖 Web API 中本插件用到的接口。
type fakeDSM struct {
	t        *testing.T
	mu       sync.Mutex
	password string
	certs    []*fakeCert
	imports  []map[string]string // 每次导入请求的字段，"order" 为字段出现顺序
	sets     int
	logouts  int
	nextID   int
	// ignoreAsDefault 模拟导入时 as_default 未生效的情况
	ignoreAsDefault bool
}

func (f *fakeDSM) makeDefault(id string) {
	for _, item := range f.certs {
		item.IsDefault = item.ID == id
	}
}

func (f *fakeDSM) find(id string) *fakeCert {
	for _, item := range f.certs {
		if item.ID == id {
			return item
		}
	}
	return nil
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
		items := []map[string]any{}
		for _, item := range f.certs {
			items = append(items, map[string]any{
				"id": item.ID, "desc": item.Desc, "is_default": item.IsDefault,
				"subject": map[string]any{"sub_alt_name": item.SAN}, "valid_till": item.ValidTill,
			})
		}
		reply(map[string]any{"success": true, "data": map[string]any{"certificates": items}})
	case "SYNO.Core.Certificate.CRT.set":
		if err := r.ParseForm(); err != nil {
			fail(100)
			return
		}
		item := f.find(r.PostForm.Get("id"))
		if item == nil {
			fail(5503)
			return
		}
		f.sets++
		item.Desc = r.PostForm.Get("desc")
		if r.PostForm.Get("as_default") == "true" {
			f.makeDefault(item.ID)
		}
		reply(map[string]any{"success": true})
	case "SYNO.Core.Certificate.import":
		fields, err := readMultipart(r)
		if err != nil {
			f.t.Errorf("导入请求不是合法的 multipart 表单: %v", err)
			fail(100)
			return
		}
		f.imports = append(f.imports, fields)
		bundle, err := certutil.ParseCertBundle([]byte(fields["file:cert"]), []byte(fields["file:key"]))
		if err != nil {
			fail(5510)
			return
		}
		item := f.find(fields["id"])
		if item == nil {
			f.nextID++
			item = &fakeCert{ID: fmt.Sprintf("new-%d", f.nextID)}
			f.certs = append(f.certs, item)
		}
		item.Desc = fields["desc"]
		item.SAN = bundle.DNSNames
		item.ValidTill = formatValidTill(bundle.NotAfter)
		if fields["as_default"] == "true" && !f.ignoreAsDefault {
			f.makeDefault(item.ID)
		}
		reply(map[string]any{"success": true, "data": map[string]any{"id": item.ID, "restart_httpd": true}})
	default:
		fail(102)
	}
}

// readMultipart 读取 multipart 表单，文件字段以 "file:" 为前缀，"order" 记录字段顺序。
func readMultipart(r *http.Request) (map[string]string, error) {
	_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}
	reader := multipart.NewReader(r.Body, params["boundary"])
	fields := map[string]string{}
	var order []string
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(part)
		if err != nil {
			return nil, err
		}
		name := part.FormName()
		order = append(order, name)
		if part.FileName() != "" {
			name = "file:" + name
		}
		fields[name] = string(data)
	}
	fields["order"] = strings.Join(order, ",")
	return fields, nil
}

// formatValidTill 按群晖的格式输出过期时间，例如 "Jan  5 12:00:00 2027 GMT"。
func formatValidTill(t time.Time) string {
	return t.UTC().Format("Jan _2 15:04:05 2006") + " GMT"
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

// 设备上没有对应证书时新建，请求格式与 acme.sh 一致
func TestDeployCreatesCertificate(t *testing.T) {
	fake, cfg := newFakeDSM(t)
	fake.certs = []*fakeCert{{ID: "self", Desc: "", IsDefault: true, SAN: []string{"synology"}, ValidTill: "Jan  5 12:00:00 2099 GMT"}}
	bundle := newBundle(t, "nas.example.com", "*.example.com")

	existed, err := Deploy(context.Background(), cfg, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if existed || len(fake.imports) != 1 {
		t.Fatalf("应新建并导入 1 次: existed=%v imports=%d", existed, len(fake.imports))
	}
	got := fake.imports[0]
	if got["order"] != "key,cert,inter_cert,id,desc" {
		t.Errorf("字段顺序应与 acme.sh 一致且不带 as_default，实际 %q", got["order"])
	}
	if got["id"] != "" || got["desc"] != "allinssl-nas.example.com" {
		t.Errorf("新建时 id 应为空、描述为默认值: id=%q desc=%q", got["id"], got["desc"])
	}
	if got["file:cert"] != bundle.Certificate || got["file:key"] != bundle.PrivateKey {
		t.Error("上传的证书或私钥内容不正确")
	}
	if !fake.find("self").IsDefault {
		t.Error("未要求设为默认时不应改变原默认证书")
	}
	if fake.logouts != 1 {
		t.Errorf("应登出 1 次，实际 %d 次", fake.logouts)
	}
}

// 续期后按描述找到原证书并原位替换，保留其默认状态
func TestDeployReplacesInPlaceAndKeepsDefault(t *testing.T) {
	fake, cfg := newFakeDSM(t)
	cfg.Desc = "我的证书"
	fake.certs = []*fakeCert{
		{ID: "old", Desc: "我的证书", IsDefault: true, SAN: []string{"nas.example.com"}, ValidTill: "Jan  5 12:00:00 2027 GMT"},
	}
	bundle := newBundle(t, "nas.example.com")

	existed, err := Deploy(context.Background(), cfg, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if existed || len(fake.imports) != 1 || len(fake.certs) != 1 {
		t.Fatalf("应原位替换而不是新建: existed=%v imports=%d certs=%d", existed, len(fake.imports), len(fake.certs))
	}
	got := fake.imports[0]
	if got["id"] != "old" || got["as_default"] != "true" || got["order"] != "key,cert,inter_cert,id,desc,as_default" {
		t.Errorf("应沿用原 ID 并保留默认状态: %v", got["order"])
	}
	if item := fake.find("old"); !item.IsDefault || item.ValidTill != formatValidTill(bundle.NotAfter) {
		t.Errorf("替换后的记录不正确: %+v", item)
	}
}

// 兼容旧版本：替换旧版本生成的 allinssl-<指纹> 记录，并改用新的描述
func TestDeployMigratesLegacyRecord(t *testing.T) {
	fake, cfg := newFakeDSM(t)
	cfg.AsDefault = true
	fake.certs = []*fakeCert{
		{ID: "self", Desc: "", IsDefault: true, SAN: []string{"synology"}, ValidTill: "Jan  5 12:00:00 2099 GMT"},
		{ID: "older", Desc: "allinssl-aaaaaa", SAN: []string{"nas.example.com"}, ValidTill: "Jan  5 12:00:00 2026 GMT"},
		{ID: "newer", Desc: "allinssl-bbbbbb", SAN: []string{"nas.example.com"}, ValidTill: "Mar  5 12:00:00 2026 GMT"},
		{ID: "other", Desc: "allinssl-cccccc", SAN: []string{"other.example.com"}, ValidTill: "Mar  5 12:00:00 2027 GMT"},
	}
	bundle := newBundle(t, "nas.example.com")

	if _, err := Deploy(context.Background(), cfg, bundle); err != nil {
		t.Fatal(err)
	}
	if len(fake.imports) != 1 || fake.imports[0]["id"] != "newer" {
		t.Fatalf("应替换域名一致且最晚过期的旧记录: %v", fake.imports)
	}
	item := fake.find("newer")
	if item.Desc != "allinssl-nas.example.com" || !item.IsDefault || fake.find("self").IsDefault {
		t.Errorf("替换后应改用新描述并成为默认证书: %+v", item)
	}
}

// 设备上已是同一张证书时不做任何修改
func TestDeploySkipsSameCertificate(t *testing.T) {
	fake, cfg := newFakeDSM(t)
	bundle := newBundle(t, "nas.example.com")
	fake.certs = []*fakeCert{
		{ID: "abc", Desc: "allinssl-nas.example.com", SAN: []string{"nas.example.com"}, ValidTill: formatValidTill(bundle.NotAfter)},
	}

	existed, err := Deploy(context.Background(), cfg, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !existed || len(fake.imports) != 0 || fake.sets != 0 {
		t.Fatalf("同一张证书不应重复上传: existed=%v imports=%d sets=%d", existed, len(fake.imports), fake.sets)
	}
}

// Force 为 true 时，同一张证书也重新上传并原位替换
func TestDeployForceReuploadsSameCertificate(t *testing.T) {
	fake, cfg := newFakeDSM(t)
	cfg.Force = true
	bundle := newBundle(t, "nas.example.com")
	fake.certs = []*fakeCert{
		{ID: "abc", Desc: "allinssl-nas.example.com", IsDefault: true, SAN: []string{"nas.example.com"}, ValidTill: formatValidTill(bundle.NotAfter)},
	}

	existed, err := Deploy(context.Background(), cfg, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if existed || len(fake.imports) != 1 || fake.imports[0]["id"] != "abc" || len(fake.certs) != 1 || !fake.find("abc").IsDefault {
		t.Fatalf("应原位重新上传并保留默认状态: existed=%v imports=%v", existed, fake.imports)
	}
}

// 证书已在设备上但还不是默认证书：只设置默认，不重复上传
func TestDeploySetsDefaultWithoutUpload(t *testing.T) {
	fake, cfg := newFakeDSM(t)
	cfg.AsDefault = true
	bundle := newBundle(t, "nas.example.com")
	fake.certs = []*fakeCert{
		{ID: "self", Desc: "", IsDefault: true, SAN: []string{"synology"}, ValidTill: "Jan  5 12:00:00 2099 GMT"},
		{ID: "abc", Desc: "allinssl-" + strings.Repeat("a", 6), SAN: []string{"nas.example.com"}, ValidTill: formatValidTill(bundle.NotAfter)},
	}

	existed, err := Deploy(context.Background(), cfg, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if existed || len(fake.imports) != 0 || fake.sets != 1 || !fake.find("abc").IsDefault {
		t.Fatalf("应只设置默认证书: existed=%v imports=%d sets=%d", existed, len(fake.imports), fake.sets)
	}
}

// 导入时 as_default 没有生效：单独再设置一次并确认
func TestDeployFallsBackToSetDefault(t *testing.T) {
	fake, cfg := newFakeDSM(t)
	cfg.AsDefault = true
	fake.ignoreAsDefault = true
	fake.certs = []*fakeCert{{ID: "self", Desc: "", IsDefault: true, SAN: []string{"synology"}, ValidTill: "Jan  5 12:00:00 2099 GMT"}}

	if _, err := Deploy(context.Background(), cfg, newBundle(t, "nas.example.com")); err != nil {
		t.Fatal(err)
	}
	if len(fake.imports) != 1 || fake.sets != 1 || !fake.find("new-1").IsDefault {
		t.Fatalf("应在导入后单独设为默认: imports=%d sets=%d", len(fake.imports), fake.sets)
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
	// 群晖格式的时间应能与证书的过期时间精确比较
	bundle := newBundle(t, "nas.example.com")
	info := certificateInfo{ValidTill: formatValidTill(bundle.NotAfter)}
	info.Subject.SubAltName = []string{"nas.example.com"}
	if !info.sameAs(bundle) {
		t.Error("同一张证书应判定为相同")
	}
	info.ValidTill = formatValidTill(bundle.NotAfter.Add(time.Hour))
	if info.sameAs(bundle) {
		t.Error("过期时间不同应判定为不同")
	}
}

func TestEnsureAPIPath(t *testing.T) {
	cases := map[string]string{
		"https://nas.example.com:5001":                  "https://nas.example.com:5001/webapi/entry.cgi",
		"https://nas.example.com:5001/":                 "https://nas.example.com:5001/webapi/entry.cgi",
		" http://192.168.1.2:5000 ":                     "http://192.168.1.2:5000/webapi/entry.cgi",
		"https://nas.example.com:5001/webapi/entry.cgi": "https://nas.example.com:5001/webapi/entry.cgi",
		"https://nas.example.com":                       "https://nas.example.com/webapi/entry.cgi",
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
