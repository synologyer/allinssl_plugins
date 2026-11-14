package synology

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"mime/multipart"
	"net/textproto"
	"regexp"
	"strings"
	"time"

	"github.com/synologyer/allinssl_plugins/internal/certutil"
)

// Config 是一次部署所需的设备信息和选项。
type Config struct {
	URL        string // 设备地址，包含协议，端口可省略
	Username   string
	Password   string
	Desc       string // 证书在群晖中的描述，留空时使用 DefaultDesc
	AsDefault  bool   // 是否设为默认证书
	SkipVerify bool   // 是否跳过设备自身 HTTPS 证书的校验
}

// validTillLayout 是群晖返回的证书时间格式，日期为一位数时可能补空格或补零。
const validTillLayout = "Jan _2 15:04:05 2006 MST"

// legacyDesc 匹配 2.0.x 及更早版本生成的描述：allinssl- 加证书指纹（6 位或 64 位十六进制）。
var legacyDesc = regexp.MustCompile(`^allinssl-([0-9a-f]{6}|[0-9a-f]{64})$`)

// DefaultDesc 返回证书在群晖中的默认描述：allinssl- 加证书的第一个域名。
//
// 描述在证书续期后保持不变，插件靠它找到上一次上传的证书并原位替换。
func DefaultDesc(bundle *certutil.CertBundle) string {
	if len(bundle.DNSNames) > 0 {
		return "allinssl-" + bundle.DNSNames[0]
	}
	return bundle.GetNoteShort()
}

// Deploy 把证书部署到群晖设备。
//
// 做法与 acme.sh 的 synology_dsm 部署脚本一致：按描述找到设备上已有的证书并
// 原位替换（沿用原证书的 ID），这样原证书的默认状态和各服务的绑定关系都会保留，
// 群晖会自行重新加载使用该证书的网页服务。找不到时才新建。
//
// 设备上已是同一张证书且无需调整默认状态时不做任何修改，返回 existed=true。
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

	desc := strings.TrimSpace(cfg.Desc)
	if desc == "" {
		desc = DefaultDesc(bundle)
	}
	return client.deployCertificate(ctx, bundle, desc, cfg.AsDefault)
}

func (c *Client) deployCertificate(ctx context.Context, bundle *certutil.CertBundle, desc string, asDefault bool) (existed bool, err error) {
	certs, err := c.listCertificates(ctx)
	if err != nil {
		return false, err
	}
	target := findTarget(certs, bundle, desc)

	// 设备上已经是这张证书：最多只需要调整默认状态
	if target != nil && target.sameAs(bundle) {
		if !asDefault || target.IsDefault {
			log.Printf("设备上已是这张证书（描述「%s」，ID %s，默认证书: %v，节点要求设为默认: %v），无需修改",
				target.Desc, target.ID, target.IsDefault, asDefault)
			return true, nil
		}
		log.Printf("证书「%s」已在设备上，仅设为默认证书", target.Desc)
		if err := c.setDefault(ctx, target.ID, target.Desc); err != nil {
			return false, err
		}
		return false, c.ensureDefault(ctx, target.ID, target.Desc, false)
	}

	var id string
	wantDefault := asDefault
	if target != nil {
		id = target.ID
		// 原位替换时保留原有的默认状态
		wantDefault = asDefault || target.IsDefault
		log.Printf("原位替换设备上的证书「%s」（ID %s，默认证书: %v）", target.Desc, target.ID, target.IsDefault)
	} else {
		log.Printf("设备上没有描述为「%s」的证书，新建", desc)
	}

	imported, err := c.importCertificate(ctx, bundle, id, desc, wantDefault)
	if err != nil {
		return false, err
	}
	log.Printf("证书已导入（ID %s），群晖是否重启了网页服务: %v", imported.ID, imported.RestartHttpd)

	if wantDefault {
		if imported.ID != "" {
			id = imported.ID
		}
		return false, c.ensureDefault(ctx, id, desc, true)
	}
	return false, nil
}

// findTarget 找出本次部署要替换的证书，找不到时返回 nil。
//
// 先按描述精确匹配；没有时兼容旧版本：旧版本每次续期都会新建一条描述为
// allinssl-<指纹> 的证书，取其中域名完全一致的一条来替换，优先默认证书，其次最晚过期的。
func findTarget(certs []certificateInfo, bundle *certutil.CertBundle, desc string) *certificateInfo {
	for i := range certs {
		if certs[i].Desc == desc {
			return &certs[i]
		}
	}

	var best *certificateInfo
	for i := range certs {
		item := &certs[i]
		if !legacyDesc.MatchString(item.Desc) || !bundle.IsDNSNamesMatch(item.Subject.SubAltName) {
			continue
		}
		switch {
		case best == nil:
			best = item
		case item.IsDefault != best.IsDefault:
			if item.IsDefault {
				best = item
			}
		case item.validTill().After(best.validTill()):
			best = item
		}
	}
	return best
}

// sameAs 判断设备上的这条记录是否就是 bundle 这张证书：域名一致且过期时间相同。
// 群晖的证书列表不返回指纹或序列号，只能用这两项判断。
func (info *certificateInfo) sameAs(bundle *certutil.CertBundle) bool {
	validTill := info.validTill()
	return !validTill.IsZero() &&
		validTill.Equal(bundle.NotAfter.Truncate(time.Second)) &&
		bundle.IsDNSNamesMatch(info.Subject.SubAltName)
}

// validTill 解析过期时间，无法解析时返回零值。
func (info *certificateInfo) validTill() time.Time {
	parsed, err := time.Parse(validTillLayout, info.ValidTill)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func (c *Client) listCertificates(ctx context.Context) ([]certificateInfo, error) {
	var list commonResponse[certificateList]
	_, err := c.R().
		SetContext(ctx).
		SetQueryParam("api", "SYNO.Core.Certificate.CRT").
		SetQueryParam("version", "1").
		SetQueryParam("method", "list").
		SetResult(&list).
		SetContentType("application/json").
		Get("")
	if err != nil {
		return nil, fmt.Errorf("获取证书列表失败: %w", err)
	}
	if !list.Success {
		if list.Error.Code == 105 {
			return nil, fmt.Errorf("获取证书列表失败（错误码 105）：该账号不是管理员，没有管理证书的权限")
		}
		return nil, fmt.Errorf("获取证书列表失败%s", errorCode(list.Error.Code))
	}
	return list.Data.Certificates, nil
}

// importCertificate 导入证书。id 非空时原位替换该证书，为空时新建。
//
// 请求格式与 acme.sh 保持一致：先是三个文件，再是 id、desc，需要设为默认时才带 as_default。
func (c *Client) importCertificate(ctx context.Context, bundle *certutil.CertBundle, id, desc string, asDefault bool) (*certificateImport, error) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	writeFile := func(field, filename, content string) error {
		header := textproto.MIMEHeader{}
		header.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, field, filename))
		header.Set("Content-Type", "application/octet-stream")
		part, err := writer.CreatePart(header)
		if err != nil {
			return err
		}
		_, err = part.Write([]byte(content))
		return err
	}
	steps := []func() error{
		func() error { return writeFile("key", "private_key.pem", bundle.PrivateKey) },
		func() error { return writeFile("cert", "certificate.pem", bundle.Certificate) },
		func() error { return writeFile("inter_cert", "ca_bundle.pem", bundle.CertificateChain) },
		func() error { return writer.WriteField("id", id) },
		func() error { return writer.WriteField("desc", desc) },
	}
	if asDefault {
		steps = append(steps, func() error { return writer.WriteField("as_default", "true") })
	}
	steps = append(steps, writer.Close)
	for _, step := range steps {
		if err := step(); err != nil {
			return nil, fmt.Errorf("生成上传请求失败: %w", err)
		}
	}

	var imported commonResponse[certificateImport]
	_, err := c.R().
		SetContext(ctx).
		SetQueryParam("api", "SYNO.Core.Certificate").
		SetQueryParam("version", "1").
		SetQueryParam("method", "import").
		SetQueryParam("SynoToken", c.token).
		SetQueryParam("_sid", c.sid).
		SetHeader("Content-Type", writer.FormDataContentType()).
		SetBody(body.Bytes()).
		SetResult(&imported).
		SetForceResponseContentType("application/json").
		Post("")
	if err != nil {
		return nil, fmt.Errorf("上传证书失败: %w", err)
	}
	if !imported.Success {
		return nil, fmt.Errorf("上传证书失败%s", errorCode(imported.Error.Code))
	}
	return &imported.Data, nil
}

// setDefault 把已有证书设为默认证书，对应群晖界面里证书的「编辑 → 设为默认证书」。
func (c *Client) setDefault(ctx context.Context, id, desc string) error {
	var resp commonResponse[struct{}]
	_, err := c.R().
		SetContext(ctx).
		SetQueryParam("api", "SYNO.Core.Certificate.CRT").
		SetQueryParam("version", "1").
		SetQueryParam("method", "set").
		SetQueryParam("SynoToken", c.token).
		SetQueryParam("_sid", c.sid).
		SetFormData(map[string]string{"id": id, "desc": desc, "as_default": "true"}).
		SetResult(&resp).
		SetForceResponseContentType("application/json").
		Post("")
	if err != nil {
		return fmt.Errorf("设为默认证书失败: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("设为默认证书失败%s", errorCode(resp.Error.Code))
	}
	return nil
}

// ensureDefault 重新读取证书列表，确认指定证书确实已是默认证书。
// retry 为 true 时，发现尚未生效会再单独设置一次。
func (c *Client) ensureDefault(ctx context.Context, id, desc string, retry bool) error {
	isDefault := func() (bool, string, error) {
		certs, err := c.listCertificates(ctx)
		if err != nil {
			return false, "", err
		}
		for _, item := range certs {
			if (id != "" && item.ID == id) || (id == "" && item.Desc == desc) {
				return item.IsDefault, item.ID, nil
			}
		}
		return false, "", fmt.Errorf("证书已上传，但在设备的证书列表中找不到「%s」", desc)
	}

	ok, foundID, err := isDefault()
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	if retry {
		log.Printf("导入后证书「%s」尚未成为默认证书，单独设置一次", desc)
		if err := c.setDefault(ctx, foundID, desc); err != nil {
			return fmt.Errorf("证书已上传，但%w", err)
		}
		if ok, _, err = isDefault(); err != nil {
			return err
		}
		if ok {
			return nil
		}
	}
	return fmt.Errorf("证书已上传，但未能设为默认证书，请在群晖「控制面板 → 安全性 → 证书」中手动设置")
}
