// synology 是 ALLinSSL 的模块插件后端，在工作流中提供「部署到群晖」节点。
//
// 本程序由 ALLinSSL 启动，不能直接运行；安装和使用方法见仓库 README。
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/synologyer/allinssl_plugins/internal/module"
	"github.com/synologyer/allinssl_plugins/internal/workflow"
)

// 日志文件名及大小上限，超过上限时在启动时清空重写。
const (
	logFileName    = "synology.log"
	logFileMaxSize = 1 << 20
)

// openLogFile 打开模块数据目录下的日志文件；目录未提供或无法写入时返回 nil，只写标准错误。
func openLogFile(dir string) *os.File {
	if dir == "" {
		return nil
	}
	path := filepath.Join(dir, logFileName)
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if info, err := os.Stat(path); err == nil && info.Size() > logFileMaxSize {
		flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}
	file, err := os.OpenFile(path, flags, 0600)
	if err != nil {
		log.Printf("无法写入日志文件 %s: %v", path, err)
		return nil
	}
	return file
}

// version 在构建时通过 -ldflags 注入，与 package/plugin.json 保持一致。
var version = "dev"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Println(version)
		return
	}

	// 标准输出留给协议的就绪消息，日志写到标准错误和模块数据目录下的日志文件。
	log.SetPrefix("[synology] ")
	log.SetOutput(os.Stderr)
	if file := openLogFile(os.Getenv(module.EnvData)); file != nil {
		defer file.Close()
		log.SetOutput(io.MultiWriter(os.Stderr, file))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	m := module.Module{
		Invoke:   workflow.Invoke,
		Workflow: workflow.Registration(),
	}
	log.Printf("插件已启动，版本 %s", version)
	if err := m.Serve(ctx); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
