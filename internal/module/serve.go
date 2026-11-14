package module

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// InvokeFunc 处理宿主的一次扩展点调用。
type InvokeFunc func(ctx context.Context, call Invoke) Reply

// Module 描述一个模块插件后端。
type Module struct {
	Invoke   InvokeFunc           // 必填，处理 /invoke
	Workflow WorkflowRegistration // 注册的工作流节点，通过 /api/workflow 提供给宿主
}

// Handler 返回插件对宿主提供的 HTTP 接口，所有请求都必须携带宿主下发的凭据。
func (m Module) Handler(token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/invoke", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var call Invoke
		if err := json.NewDecoder(r.Body).Decode(&call); err != nil {
			http.Error(w, "模块请求无效", http.StatusBadRequest)
			return
		}
		writeJSON(w, m.Invoke(r.Context(), call))
	})
	mux.HandleFunc("/api/workflow", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, m.Workflow)
	})

	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Authorization"))
		if token == "" || subtle.ConstantTimeCompare(got, want) != 1 {
			http.Error(w, "模块凭据无效", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// Serve 启动模块并阻塞，直到 ctx 结束或宿主关闭标准输入。
//
// 标准输出只用于输出一行就绪消息，日志请写到标准错误。
func (m Module) Serve(ctx context.Context) error {
	if m.Invoke == nil {
		return errors.New("module: Invoke 不能为空")
	}
	token := os.Getenv(EnvToken)
	if token == "" {
		return errors.New("本程序是 ALLinSSL 模块插件，请放入 ALLinSSL 插件目录并在「插件管理」中启用，不能直接运行")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("监听本机端口失败: %w", err)
	}
	server := &http.Server{Handler: m.Handler(token), ReadHeaderTimeout: 10 * time.Second}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ready := map[string]any{"protocol": Protocol, "url": "http://" + listener.Addr().String()}
	if err := json.NewEncoder(os.Stdout).Encode(ready); err != nil {
		listener.Close()
		return fmt.Errorf("输出就绪消息失败: %w", err)
	}

	// 宿主通过关闭标准输入通知插件退出。
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		cancel()
	}()

	shutdownDone := make(chan error, 1)
	go func() {
		<-ctx.Done()
		shutdownCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		err := server.Shutdown(shutdownCtx)
		if err != nil {
			_ = server.Close()
		}
		shutdownDone <- err
	}()

	err = server.Serve(listener)
	cancel()
	shutdownErr := <-shutdownDone
	if errors.Is(err, http.ErrServerClosed) {
		return shutdownErr
	}
	return err
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
