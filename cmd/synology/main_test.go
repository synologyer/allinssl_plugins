package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/synologyer/allinssl_plugins/internal/module"
	"github.com/synologyer/allinssl_plugins/internal/testcert"
)

// TestManifest 按 ALLinSSL 对 plugin.json 的校验规则检查插件清单。
func TestManifest(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "package", "plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Type     string `json:"type"`
		ID       string `json:"id"`
		Name     string `json:"name"`
		Version  string `json:"version"`
		Protocol int    `json:"protocol"`
		Backend  string `json:"backend"`
		Frontend struct {
			Entry string `json:"entry"`
		} `json:"frontend"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Type != "module" || manifest.Protocol != module.Protocol {
		t.Errorf("type/protocol 不正确: %+v", manifest)
	}
	if !regexp.MustCompile(`^[a-z][a-z0-9_-]*$`).MatchString(manifest.ID) {
		t.Errorf("模块标识无效: %q", manifest.ID)
	}
	if manifest.Name == "" || manifest.Version == "" || manifest.Backend == "" {
		t.Errorf("名称、版本和后端入口不能为空: %+v", manifest)
	}
	if !strings.HasPrefix(manifest.Frontend.Entry, "frontend/") {
		t.Errorf("前端入口必须位于 frontend 目录: %q", manifest.Frontend.Entry)
	}
	if _, err := os.Stat(filepath.Join("..", "..", "package", manifest.Frontend.Entry)); err != nil {
		t.Errorf("前端入口文件不存在: %v", err)
	}
}

// TestHostProtocol 按 ALLinSSL 启动模块的方式运行编译后的程序，走完整个流程：
// 就绪消息 → 读取工作流注册表 → 调用部署节点 → 关闭标准输入后退出。
func TestHostProtocol(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "synology")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("编译失败: %v\n%s", err, output)
	}

	const token = "host-token"
	dataDir := t.TempDir()
	cmd := exec.Command(binary)
	cmd.Env = append(os.Environ(), module.EnvToken+"="+token, module.EnvID+"=synology", module.EnvData+"="+dataDir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	t.Cleanup(func() {
		stdin.Close()
		_ = cmd.Process.Kill()
	})

	// 就绪消息：标准输出第一行，地址必须是 http://127.0.0.1:端口
	line, err := bufio.NewReader(stdout).ReadBytes('\n')
	if err != nil {
		t.Fatalf("读取就绪消息失败: %v\n%s", err, stderr.String())
	}
	go func() {
		_, _ = io.Copy(io.Discard, stdout)
		exited <- cmd.Wait()
	}()
	var ready struct {
		Protocol int    `json:"protocol"`
		URL      string `json:"url"`
	}
	if err := json.Unmarshal(line, &ready); err != nil {
		t.Fatalf("就绪消息不是 JSON: %s", line)
	}
	address, err := url.Parse(ready.URL)
	if err != nil {
		t.Fatal(err)
	}
	if ready.Protocol != 1 || address.Scheme != "http" || address.Hostname() != "127.0.0.1" || address.Port() == "" || address.Path != "" {
		t.Fatalf("就绪消息不符合协议: %s", line)
	}

	call := func(method, path, body string) (*http.Response, []byte) {
		t.Helper()
		request, err := http.NewRequest(method, ready.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		return response, data
	}

	// 工作流注册表
	response, data := call("GET", "/api/workflow", "")
	if response.StatusCode != http.StatusOK || !strings.Contains(string(data), `"name":"synology_deploy"`) {
		t.Fatalf("工作流注册表不正确: %d %s", response.StatusCode, data)
	}

	// 调用部署节点，目标是一台模拟的群晖设备
	var mu sync.Mutex
	imported := 0
	device := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("method") {
		case "login":
			io.WriteString(w, `{"success":true,"data":{"sid":"s","synotoken":"t"}}`)
		case "list":
			io.WriteString(w, `{"success":true,"data":{"certificates":[]}}`)
		case "import":
			mu.Lock()
			imported++
			mu.Unlock()
			io.WriteString(w, `{"success":true,"data":{"id":"1"}}`)
		default:
			io.WriteString(w, `{"success":true}`)
		}
	}))
	device.TLS = &tls.Config{}
	device.StartTLS()
	defer device.Close()

	certPEM, keyPEM, err := testcert.Valid("nas.example.com")
	if err != nil {
		t.Fatal(err)
	}
	invoke, _ := json.Marshal(module.Invoke{
		Kind: "workflow", Target: "plugin:synology:synology_deploy", Stage: "replace", Handler: "deploy",
		Params: map[string]any{
			"url": device.URL, "username": "admin", "password": "secret", "as_default": true,
			"certificate": map[string]any{"cert": certPEM, "key": keyPEM},
			"_runId":      "1", "NodeId": "node-1",
		},
	})
	response, data = call("POST", "/invoke", string(invoke))
	var reply module.Reply
	if err := json.Unmarshal(data, &reply); err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("调用响应无效: %d %s", response.StatusCode, data)
	}
	if reply.Error != "" {
		t.Fatalf("部署失败: %s", reply.Error)
	}
	if imported != 1 {
		t.Fatalf("应向设备导入 1 次证书，实际 %d 次", imported)
	}

	// 失败时通过 error 字段返回，不影响进程
	response, data = call("POST", "/invoke", `{"kind":"workflow","handler":"deploy","params":{}}`)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(data), `"error"`) {
		t.Fatalf("配置缺失应返回 error 字段: %d %s", response.StatusCode, data)
	}

	// 宿主关闭标准输入后，插件应自行退出
	stdin.Close()
	select {
	case err := <-exited:
		if err != nil {
			t.Fatalf("插件退出状态异常: %v\n%s", err, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("关闭标准输入后插件没有退出")
	}

	// 部署结果和失败原因都应写入数据目录下的日志文件
	logData, err := os.ReadFile(filepath.Join(dataDir, logFileName))
	if err != nil {
		t.Fatalf("没有生成日志文件: %v", err)
	}
	for _, want := range []string{"证书已上传到", "部署到群晖失败"} {
		if !strings.Contains(string(logData), want) {
			t.Errorf("日志文件缺少 %q:\n%s", want, logData)
		}
	}
}
