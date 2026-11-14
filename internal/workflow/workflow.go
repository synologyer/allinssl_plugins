// Package workflow 实现插件注册到 ALLinSSL 工作流中的节点。
package workflow

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/synologyer/allinssl_plugins/internal/certutil"
	"github.com/synologyer/allinssl_plugins/internal/module"
	"github.com/synologyer/allinssl_plugins/internal/synology"
)

// 节点名称与处理器名称，前端入口 package/frontend/index.js 中的节点名需与此一致。
const (
	NodeDeploy    = "deploy"
	HandlerDeploy = "deploy"
)

// Registration 返回本插件注册的工作流节点。
func Registration() module.WorkflowRegistration {
	return module.WorkflowRegistration{
		Nodes: []module.WorkflowNode{
			{Name: NodeDeploy, Handler: HandlerDeploy, Title: "部署到群晖", Order: 6},
		},
	}
}

// Invoke 处理宿主的扩展点调用。
func Invoke(ctx context.Context, call module.Invoke) module.Reply {
	if call.Kind != "workflow" || call.Handler != HandlerDeploy {
		return module.Reply{Error: fmt.Sprintf("不支持的调用: %s/%s", call.Kind, call.Handler)}
	}
	if err := deploy(ctx, call.Params); err != nil {
		log.Printf("部署到群晖失败: %v", err)
		return module.Reply{Error: err.Error()}
	}
	// 与内置部署节点一致，不向后续节点输出数据。
	return module.Reply{}
}

func deploy(ctx context.Context, params map[string]any) error {
	cfg, err := parseConfig(params)
	if err != nil {
		return err
	}
	bundle, err := parseCertificate(params)
	if err != nil {
		return err
	}
	existed, err := synology.Deploy(ctx, cfg, bundle)
	if err != nil {
		return err
	}
	if existed {
		log.Printf("证书已存在于 %s，跳过上传: %v", cfg.URL, bundle.DNSNames)
	} else {
		log.Printf("证书已上传到 %s: %v", cfg.URL, bundle.DNSNames)
	}
	return nil
}

// parseConfig 读取节点配置。
func parseConfig(params map[string]any) (synology.Config, error) {
	cfg := synology.Config{SkipVerify: true}
	var err error
	if cfg.URL, err = requiredString(params, "url", "设备地址"); err != nil {
		return cfg, err
	}
	if cfg.Username, err = requiredString(params, "username", "用户名"); err != nil {
		return cfg, err
	}
	if cfg.Password, err = requiredString(params, "password", "密码"); err != nil {
		return cfg, err
	}
	if cfg.AsDefault, err = optionalBool(params, "as_default", false); err != nil {
		return cfg, err
	}
	if cfg.SkipVerify, err = optionalBool(params, "skip_verify", true); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// parseCertificate 取出宿主传入的证书。
//
// 节点选择了证书来源时宿主放在 certificate 中；否则使用上一个节点的输出 fromNodeData。
func parseCertificate(params map[string]any) (*certutil.CertBundle, error) {
	for _, key := range []string{"certificate", "fromNodeData"} {
		data, ok := params[key].(map[string]any)
		if !ok {
			continue
		}
		cert, _ := data["cert"].(string)
		keyPEM, _ := data["key"].(string)
		if strings.TrimSpace(cert) == "" || strings.TrimSpace(keyPEM) == "" {
			continue
		}
		// 证书内容只有站点证书时，补上单独给出的中间证书。
		if issuer, _ := data["issuerCert"].(string); issuer != "" && strings.Count(cert, "BEGIN CERTIFICATE") == 1 {
			cert = strings.TrimRight(cert, "\r\n") + "\n" + issuer
		}
		bundle, err := certutil.ParseCertBundle([]byte(cert), []byte(keyPEM))
		if err != nil {
			return nil, fmt.Errorf("解析证书失败: %w", err)
		}
		return bundle, nil
	}
	return nil, errors.New("没有可部署的证书：请在节点设置中选择证书来源，或把节点放在申请/上传证书节点之后")
}

func requiredString(params map[string]any, key, label string) (string, error) {
	value, _ := params[key].(string)
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("节点配置缺少%s（%s）", label, key)
	}
	return value, nil
}

// optionalBool 兼容布尔值和 "true"/"false" 字符串两种写法。
func optionalBool(params map[string]any, key string, fallback bool) (bool, error) {
	switch value := params[key].(type) {
	case nil:
		return fallback, nil
	case bool:
		return value, nil
	case string:
		if strings.TrimSpace(value) == "" {
			return fallback, nil
		}
		parsed, err := strconv.ParseBool(strings.TrimSpace(value))
		if err != nil {
			return false, fmt.Errorf("节点配置 %s 必须是布尔值", key)
		}
		return parsed, nil
	default:
		return false, fmt.Errorf("节点配置 %s 必须是布尔值", key)
	}
}
