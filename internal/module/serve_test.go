package module

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	m := Module{
		Invoke: func(_ context.Context, call Invoke) Reply {
			return Reply{Result: map[string]any{"handler": call.Handler, "url": call.Params["url"]}}
		},
		Workflow: WorkflowRegistration{Nodes: []WorkflowNode{{Name: "deploy", Handler: "deploy"}}},
	}
	server := httptest.NewServer(m.Handler("secret"))
	t.Cleanup(server.Close)
	return server
}

func do(t *testing.T, method, url, token, body string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { response.Body.Close() })
	return response
}

func TestHandlerRequiresToken(t *testing.T) {
	server := newTestServer(t)
	for _, token := range []string{"", "wrong"} {
		if response := do(t, "GET", server.URL+"/api/workflow", token, ""); response.StatusCode != http.StatusUnauthorized {
			t.Errorf("凭据 %q 应返回 401，实际 %d", token, response.StatusCode)
		}
	}
	// 未配置凭据时拒绝所有请求
	open := httptest.NewServer(Module{Invoke: func(context.Context, Invoke) Reply { return Reply{} }}.Handler(""))
	defer open.Close()
	if response := do(t, "GET", open.URL+"/api/workflow", "", ""); response.StatusCode != http.StatusUnauthorized {
		t.Errorf("空凭据应返回 401，实际 %d", response.StatusCode)
	}
}

func TestHandlerWorkflowRegistration(t *testing.T) {
	server := newTestServer(t)
	response := do(t, "GET", server.URL+"/api/workflow", "secret", "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("状态码 %d", response.StatusCode)
	}
	var registration WorkflowRegistration
	if err := json.NewDecoder(response.Body).Decode(&registration); err != nil {
		t.Fatal(err)
	}
	if len(registration.Nodes) != 1 || registration.Nodes[0].Name != "deploy" || registration.Nodes[0].Handler != "deploy" {
		t.Fatalf("注册表不正确: %+v", registration)
	}
}

func TestHandlerInvoke(t *testing.T) {
	server := newTestServer(t)
	body := `{"kind":"workflow","target":"plugin:synology:deploy","stage":"replace","handler":"deploy","params":{"url":"https://nas"}}`
	response := do(t, "POST", server.URL+"/invoke", "secret", body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("状态码 %d", response.StatusCode)
	}
	var reply Reply
	if err := json.NewDecoder(response.Body).Decode(&reply); err != nil {
		t.Fatal(err)
	}
	result, _ := reply.Result.(map[string]any)
	if result["handler"] != "deploy" || result["url"] != "https://nas" {
		t.Fatalf("响应不正确: %+v", reply)
	}

	if response := do(t, "GET", server.URL+"/invoke", "secret", ""); response.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /invoke 应返回 405，实际 %d", response.StatusCode)
	}
	if response := do(t, "POST", server.URL+"/invoke", "secret", "not json"); response.StatusCode != http.StatusBadRequest {
		t.Errorf("无效请求体应返回 400，实际 %d", response.StatusCode)
	}
}
