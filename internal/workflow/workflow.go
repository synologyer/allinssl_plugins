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
//
// 节点名不能与宿主内置节点（apply、deploy、upload、notify 等）同名：
// 宿主前端会把同名节点当作内置节点处理，导致注册失败。
const (
	NodeDeploy    = "synology_deploy"
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
	skipped, err := deploy(ctx, call.Params)
	if err != nil {
		log.Printf("部署到群晖失败: %v", err)
		return module.Reply{Error: err.Error()}
	}
	// 与内置部署节点一致：实际部署时不输出数据；跳过时输出 skip，
	// 后续的通知节点据此可以不重复发送通知。
	if skipped {
		return module.Reply{Result: map[string]any{"skip": true}}
	}
	return module.Reply{}
}

// deploy 执行部署，skipped 表示证书没有变化而未做任何修改。
//
// 「重复部署」选项为跳过时（默认），行为与内置部署节点一致：本节点上次成功部署的
// 就是这张证书时直接跳过，不连接设备；没有记录时再与设备上的证书比较。
// 选项为不跳过时，即使证书相同也重新上传并原位替换。
func deploy(ctx context.Context, params map[string]any) (skipped bool, err error) {
	cfg, err := parseConfig(params)
	if err != nil {
		return false, err
	}
	skip, err := optionalBool(params, "skip", true)
	if err != nil {
		return false, err
	}
	bundle, err := parseCertificate(params)
	if err != nil {
		return false, err
	}

	nodeID, _ := params["NodeId"].(string)
	certHash := bundle.GetFingerprintSHA256()
	targetHash := hashStrings(cfg.URL, cfg.Desc, strconv.FormatBool(cfg.AsDefault))
	if skip && store.matches(nodeID, certHash, targetHash) {
		log.Printf("与上次部署到 %s 的证书相同且上次部署成功，跳过重复部署: %v", cfg.URL, bundle.DNSNames)
		return true, nil
	}

	cfg.Force = !skip
	log.Printf("开始部署到 %s（用户 %s，证书域名 %v，重复部署: %s）", cfg.URL, cfg.Username, bundle.DNSNames, skipLabel(skip))
	existed, err := synology.Deploy(ctx, cfg, bundle)
	if err != nil {
		store.forget(nodeID)
		return false, err
	}
	store.save(nodeID, certHash, targetHash)
	if existed {
		log.Printf("设备 %s 上已是这张证书，跳过上传: %v", cfg.URL, bundle.DNSNames)
	} else {
		log.Printf("证书已部署到 %s: %v", cfg.URL, bundle.DNSNames)
	}
	return existed, nil
}

func skipLabel(skip bool) string {
	if skip {
		return "跳过"
	}
	return "不跳过"
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
	if desc, ok := params["cert_desc"].(string); ok {
		cfg.Desc = strings.TrimSpace(desc)
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

// optionalBool 兼容布尔值、数字 1/0 和 "true"/"false"/"1"/"0" 字符串几种写法。
func optionalBool(params map[string]any, key string, fallback bool) (bool, error) {
	switch value := params[key].(type) {
	case nil:
		return fallback, nil
	case bool:
		return value, nil
	case float64:
		return value != 0, nil
	case int:
		return value != 0, nil
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
