package workflow

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/synologyer/allinssl_plugins/internal/certutil"
	"github.com/synologyer/allinssl_plugins/internal/module"
	"github.com/synologyer/allinssl_plugins/internal/synology"
	"github.com/synologyer/allinssl_plugins/internal/testcert"
)

func TestRegistration(t *testing.T) {
	// 宿主要求节点名称匹配该格式，且处理器不能为空
	identifier := regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
	nodes := Registration().Nodes
	if len(nodes) != 1 {
		t.Fatalf("应注册 1 个节点，实际 %d 个", len(nodes))
	}
	if !identifier.MatchString(nodes[0].Name) || nodes[0].Handler == "" {
		t.Fatalf("节点声明无效: %+v", nodes[0])
	}

	// 宿主前端把这些名称当作内置节点，插件节点不能与之同名
	builtin := []string{"apply", "deploy", "upload", "notify", "private_ca", "start", "branch", "condition", "execute_result_branch", "execute_result_condition"}
	for _, name := range builtin {
		if nodes[0].Name == name {
			t.Fatalf("节点名 %q 与宿主内置节点同名", name)
		}
	}

	// 前端入口注册的节点名必须与后端一致
	entry, err := os.ReadFile(filepath.Join("..", "..", "package", "frontend", "index.js"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(entry), "const NODE_NAME = '"+nodes[0].Name+"'") {
		t.Fatalf("前端入口的节点名与后端 %q 不一致", nodes[0].Name)
	}
}

func TestParseConfig(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"url": " https://nas:5001 ", "username": "admin", "password": "secret"}
	}

	cfg, err := parseConfig(base())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.URL != "https://nas:5001" || cfg.AsDefault || !cfg.SkipVerify || cfg.Desc != "" {
		t.Errorf("默认值不正确: %+v", cfg)
	}

	// 布尔值和字符串两种写法都接受
	for _, value := range []any{true, "true", " TRUE "} {
		params := base()
		params["as_default"] = value
		params["skip_verify"] = "false"
		params["cert_desc"] = " 我的证书 "
		cfg, err := parseConfig(params)
		if err != nil || !cfg.AsDefault || cfg.SkipVerify || cfg.Desc != "我的证书" {
			t.Errorf("as_default=%#v: cfg=%+v err=%v", value, cfg, err)
		}
	}

	params := base()
	params["as_default"] = "yes please"
	if _, err := parseConfig(params); err == nil {
		t.Error("无法识别的布尔值应返回错误")
	}

	for _, key := range []string{"url", "username", "password"} {
		params := base()
		delete(params, key)
		if _, err := parseConfig(params); err == nil || !strings.Contains(err.Error(), key) {
			t.Errorf("缺少 %s 时应返回错误，实际: %v", key, err)
		}
	}
}

func TestParseCertificate(t *testing.T) {
	leaf, key, err := testcert.Valid("nas.example.com")
	if err != nil {
		t.Fatal(err)
	}
	issuer, _, err := testcert.Valid("ca.example.com")
	if err != nil {
		t.Fatal(err)
	}

	// 选择了证书来源：宿主放在 certificate 中
	bundle, err := parseCertificate(map[string]any{"certificate": map[string]any{"cert": leaf, "key": key}})
	if err != nil || bundle.DNSNames[0] != "nas.example.com" {
		t.Fatalf("certificate 解析失败: %v", err)
	}

	// 未选择来源：使用上一个节点的输出；中间证书单独给出时自动补上
	bundle, err = parseCertificate(map[string]any{"fromNodeData": map[string]any{"cert": leaf, "key": key, "issuerCert": issuer}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(bundle.CertificateChain, "BEGIN CERTIFICATE") != 1 {
		t.Error("应补上中间证书")
	}

	// 证书内容已包含证书链时不重复追加
	bundle, err = parseCertificate(map[string]any{"certificate": map[string]any{"cert": leaf + issuer, "key": key, "issuerCert": issuer}})
	if err != nil || strings.Count(bundle.CertificateChain, "BEGIN CERTIFICATE") != 1 {
		t.Errorf("证书链不应重复: %v", err)
	}

	// 上一个节点不产出证书（例如内置部署节点返回 skip）
	if _, err := parseCertificate(map[string]any{"fromNodeData": map[string]any{"skip": true}}); err == nil {
		t.Error("没有证书时应返回错误")
	}
	if _, err := parseCertificate(map[string]any{"certificate": map[string]any{"cert": "not pem", "key": key}}); err == nil {
		t.Error("证书内容无效时应返回错误")
	}
}

func TestInvokeRejectsUnknownCall(t *testing.T) {
	for _, call := range []module.Invoke{
		{Kind: "http", Handler: HandlerDeploy},
		{Kind: "workflow", Handler: "other"},
	} {
		if reply := Invoke(context.Background(), call); reply.Error == "" {
			t.Errorf("调用 %+v 应返回错误", call)
		}
	}
}

func TestInvokeReportsConfigError(t *testing.T) {
	reply := Invoke(context.Background(), module.Invoke{Kind: "workflow", Handler: HandlerDeploy, Params: map[string]any{}})
	if !strings.Contains(reply.Error, "url") {
		t.Fatalf("应提示缺少设备地址，实际: %q", reply.Error)
	}
}

// 设备上已有同一张证书时输出 skip，实际上传时不输出数据，与内置部署节点一致。
func TestInvokeReportsSkip(t *testing.T) {
	certPEM, keyPEM, err := testcert.Valid("nas.example.com")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := certutil.ParseCertBundle([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}

	existing := false
	device := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("method") {
		case "login":
			io.WriteString(w, `{"success":true,"data":{"sid":"s","synotoken":"t"}}`)
		case "list":
			if existing {
				validTill := bundle.NotAfter.UTC().Format("Jan _2 15:04:05 2006") + " GMT"
				io.WriteString(w, `{"success":true,"data":{"certificates":[{"id":"1","desc":"`+synology.DefaultDesc(bundle)+
					`","subject":{"sub_alt_name":["nas.example.com"]},"valid_till":"`+validTill+`"}]}}`)
				return
			}
			io.WriteString(w, `{"success":true,"data":{"certificates":[]}}`)
		default:
			io.WriteString(w, `{"success":true,"data":{"id":"1"}}`)
		}
	}))
	defer device.Close()

	call := module.Invoke{Kind: "workflow", Handler: HandlerDeploy, Params: map[string]any{
		"url": device.URL, "username": "admin", "password": "secret",
		"certificate": map[string]any{"cert": certPEM, "key": keyPEM},
	}}

	if reply := Invoke(context.Background(), call); reply.Error != "" || reply.Result != nil {
		t.Fatalf("实际上传时不应输出数据: %+v", reply)
	}

	existing = true
	reply := Invoke(context.Background(), call)
	result, _ := reply.Result.(map[string]any)
	if reply.Error != "" || result["skip"] != true {
		t.Fatalf("证书已存在时应输出 skip: %+v", reply)
	}
}

// 「重复部署」选项：与内置部署节点一致，按本节点上次成功部署的证书判断是否跳过。
func TestRepeatDeployOption(t *testing.T) {
	SetDataDir(t.TempDir())
	t.Cleanup(func() { SetDataDir("") })

	certPEM, keyPEM, err := testcert.Valid("nas.example.com")
	if err != nil {
		t.Fatal(err)
	}
	requests, imports := 0, 0
	loginOK := true
	device := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("method") {
		case "login":
			if !loginOK {
				io.WriteString(w, `{"success":false,"error":{"code":400}}`)
				return
			}
			io.WriteString(w, `{"success":true,"data":{"sid":"s","synotoken":"t"}}`)
		case "list":
			io.WriteString(w, `{"success":true,"data":{"certificates":[]}}`)
		case "import":
			imports++
			io.WriteString(w, `{"success":true,"data":{"id":"1"}}`)
		default:
			io.WriteString(w, `{"success":true}`)
		}
	}))
	defer device.Close()

	params := func(extra map[string]any) map[string]any {
		values := map[string]any{
			"url": device.URL, "username": "admin", "password": "secret", "NodeId": "node-1",
			"certificate": map[string]any{"cert": certPEM, "key": keyPEM},
		}
		for key, value := range extra {
			values[key] = value
		}
		return values
	}
	invoke := func(extra map[string]any) module.Reply {
		return Invoke(context.Background(), module.Invoke{Kind: "workflow", Handler: HandlerDeploy, Params: params(extra)})
	}
	skipped := func(reply module.Reply) bool {
		result, _ := reply.Result.(map[string]any)
		return result["skip"] == true
	}

	// 第一次：实际部署
	if reply := invoke(nil); reply.Error != "" || skipped(reply) || imports != 1 {
		t.Fatalf("第一次应实际部署: %+v imports=%d", reply, imports)
	}

	// 第二次：证书相同且上次成功，跳过且不连接设备（默认即为跳过，写成 1 也一样）
	before := requests
	for _, extra := range []map[string]any{nil, {"skip": float64(1)}, {"skip": true}} {
		if reply := invoke(extra); reply.Error != "" || !skipped(reply) {
			t.Fatalf("应跳过重复部署: %+v", reply)
		}
	}
	if requests != before || imports != 1 {
		t.Fatalf("跳过时不应连接设备: requests %d -> %d", before, requests)
	}

	// 其他节点没有部署记录，不受影响
	if reply := invoke(map[string]any{"NodeId": "node-2"}); reply.Error != "" || skipped(reply) || imports != 2 {
		t.Fatalf("另一个节点应实际部署: %+v imports=%d", reply, imports)
	}

	// 选项为不跳过：证书相同也重新上传
	if reply := invoke(map[string]any{"skip": float64(0)}); reply.Error != "" || skipped(reply) || imports != 3 {
		t.Fatalf("不跳过时应重新上传: %+v imports=%d", reply, imports)
	}

	// 目标变了（例如改了证书描述）：重新部署
	if reply := invoke(map[string]any{"cert_desc": "另一个描述"}); reply.Error != "" || skipped(reply) || imports != 4 {
		t.Fatalf("修改配置后应重新部署: %+v imports=%d", reply, imports)
	}

	// 部署失败后清除记录，下次不会被跳过
	loginOK = false
	if reply := invoke(map[string]any{"skip": float64(0)}); reply.Error == "" {
		t.Fatal("登录失败应返回错误")
	}
	loginOK = true
	if reply := invoke(nil); reply.Error != "" || skipped(reply) || imports != 5 {
		t.Fatalf("上次失败后应重新部署: %+v imports=%d", reply, imports)
	}
}
