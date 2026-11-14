package synology

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/synologyer/allinssl_plugins/internal/certutil"
)

// Config 是一次部署所需的设备信息和选项。
type Config struct {
	URL        string // 设备地址，包含协议和端口
	Username   string
	Password   string
	AsDefault  bool // 是否设为默认证书
	SkipVerify bool // 是否跳过设备自身 HTTPS 证书的校验
}

// validTillLayout 是群晖返回的证书过期时间格式，日期为一位数时可能补空格或补零。
const validTillLayout = "Jan _2 15:04:05 2006 MST"

// Deploy 把证书导入到群晖设备的证书管理中。
//
// 设备上已有同一张证书且未过期时不重复上传，返回 existed=true；
// 同一张证书已过期时覆盖原记录。
func Deploy(ctx context.Context, cfg Config, bundle *certutil.CertBundle) (existed bool, err error) {
	if bundle.IsExpired() {
		return false, fmt.Errorf("证书不在有效期内（%s 至 %s）",
			bundle.NotBefore.Format(time.DateTime), bundle.NotAfter.Format(time.DateTime))
	}

	client, err := NewClient(cfg.URL, cfg.Username, cfg.Password, cfg.SkipVerify)
	if err != nil {
		return false, err
	}
	defer client.Close()

	if err := client.Login(ctx); err != nil {
		return false, err
	}
	defer func() {
		// 登出不受调用方取消影响，失败只记录日志，不影响部署结果。
		logoutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		if logoutErr := client.Logout(logoutCtx); logoutErr != nil {
			log.Printf("群晖登出失败: %v", logoutErr)
		}
	}()

	return client.importCertificate(ctx, bundle, cfg.AsDefault)
}

func (c *Client) importCertificate(ctx context.Context, bundle *certutil.CertBundle, asDefault bool) (existed bool, err error) {
	// 1. 获取证书列表，查找此前由本插件上传的同一张证书
	var list commonResponse[certificateList]
	_, err = c.R().
		SetContext(ctx).
		SetQueryParam("api", "SYNO.Core.Certificate.CRT").
		SetQueryParam("version", "1").
		SetQueryParam("method", "list").
		SetResult(&list).
		SetContentType("application/json").
		Get("")
	if err != nil {
		return false, fmt.Errorf("获取证书列表失败: %w", err)
	}
	if !list.Success {
		return false, fmt.Errorf("获取证书列表失败%s", errorCode(list.Error.Code))
	}

	note := bundle.GetNoteShort()
	var existID string
	for _, item := range list.Data.Certificates {
		if !strings.EqualFold(item.Desc, note) || !bundle.IsDNSNamesMatch(item.Subject.SubAltName) {
			continue
		}
		existID = item.ID
		validTill, parseErr := time.Parse(validTillLayout, item.ValidTill)
		if parseErr != nil {
			return false, fmt.Errorf("解析设备上证书的过期时间失败: %w", parseErr)
		}
		if validTill.After(time.Now()) {
			return true, nil
		}
		break
	}

	// 2. 导入证书，已存在但过期的记录按 ID 覆盖
	form := map[string]string{
		"desc":       note,
		"as_default": strconv.FormatBool(asDefault),
	}
	if existID != "" {
		form["id"] = existID
	}
	var imported commonResponse[certificateImport]
	_, err = c.R().
		SetContext(ctx).
		SetQueryParam("api", "SYNO.Core.Certificate").
		SetQueryParam("version", "1").
		SetQueryParam("method", "import").
		SetFormData(form).
		SetFileReader("cert", "certificate.pem", strings.NewReader(bundle.Certificate)).
		SetFileReader("key", "private_key.pem", strings.NewReader(bundle.PrivateKey)).
		SetFileReader("inter_cert", "ca_bundle.pem", strings.NewReader(bundle.CertificateChain)).
		SetResult(&imported).
		SetContentType("application/json").
		SetForceResponseContentType("application/json").
		Post("")
	if err != nil {
		return false, fmt.Errorf("上传证书失败: %w", err)
	}
	if !imported.Success {
		return false, fmt.Errorf("上传证书失败%s", errorCode(imported.Error.Code))
	}
	return false, nil
}
