// synology 是 ALLinSSL 的模块插件后端，在工作流中提供「部署到群晖」节点。
//
// 本程序由 ALLinSSL 启动，不能直接运行；安装和使用方法见仓库 README。
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/synologyer/allinssl_plugins/internal/module"
	"github.com/synologyer/allinssl_plugins/internal/workflow"
)

// version 在构建时通过 -ldflags 注入，与 package/plugin.json 保持一致。
var version = "dev"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Println(version)
		return
	}

	// 标准输出留给协议的就绪消息，日志统一写到标准错误。
	log.SetOutput(os.Stderr)
	log.SetPrefix("[synology] ")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	m := module.Module{
		Invoke:   workflow.Invoke,
		Workflow: workflow.Registration(),
	}
	if err := m.Serve(ctx); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
