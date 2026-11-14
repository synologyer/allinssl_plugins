# ALLinSSL 模块插件：群晖证书部署
PLUGIN_ID := synology
VERSION   := $(shell sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' package/plugin.json)
PLATFORMS := linux/amd64 linux/arm64
LDFLAGS   := -s -w -X main.version=$(VERSION)

.PHONY: help build package bundle test vet fmt tidy clean

help: ## 显示可用命令
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  make %-9s %s\n", $$1, $$2}'

build: ## 按当前系统和架构生成插件目录 dist/synology
	@$(MAKE) --no-print-directory bundle TARGET=. GOOS=$(shell go env GOOS) GOARCH=$(shell go env GOARCH)
	@echo "已生成 dist/$(PLUGIN_ID)"

package: ## 生成各平台的发布包 dist/synology_<版本>_<系统>_<架构>.tar.gz
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		$(MAKE) --no-print-directory bundle TARGET=$$os-$$arch GOOS=$$os GOARCH=$$arch || exit 1; \
		tar -czf dist/$(PLUGIN_ID)_$(VERSION)_$${os}_$${arch}.tar.gz -C dist/$$os-$$arch $(PLUGIN_ID) || exit 1; \
		echo "已生成 dist/$(PLUGIN_ID)_$(VERSION)_$${os}_$${arch}.tar.gz"; \
	done

# 内部目标：把清单、前端入口和后端程序组装成 dist/<TARGET>/synology
bundle:
	@mkdir -p dist/$(TARGET)/$(PLUGIN_ID)/bin dist/$(TARGET)/$(PLUGIN_ID)/frontend
	@cp package/plugin.json dist/$(TARGET)/$(PLUGIN_ID)/
	@cp package/frontend/index.js dist/$(TARGET)/$(PLUGIN_ID)/frontend/
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags "$(LDFLAGS)" \
		-o dist/$(TARGET)/$(PLUGIN_ID)/bin/$(PLUGIN_ID) ./cmd/synology

test: ## 运行单元测试
	go test ./...

vet: ## 静态检查
	go vet ./...

fmt: ## 格式化代码
	gofmt -w cmd internal

tidy: ## 整理依赖
	go mod tidy

clean: ## 删除构建产物
	rm -rf dist
