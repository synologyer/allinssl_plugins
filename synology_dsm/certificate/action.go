package certificate

import (
	"fmt"
	"strings"
	"time"

	"github.com/synologyer/allinssl_plugins/core"
	"github.com/synologyer/allinssl_plugins/synology_dsm/openapi"
	"github.com/synologyer/allinssl_plugins/synology_dsm/types"
)

// 上传证书
// isExist: 是否存在
func Action(openapiClient *openapi.Client, certBundle *core.CertBundle, as_default string) (isExist bool, err error) {

	// 1. 获取证书列表
	var certListResp types.CommonResponse[types.CertificateListResponse]
	_, err = openapiClient.R().
		SetQueryParam("api", "SYNO.Core.Certificate.CRT").
		SetQueryParam("version", "1").
		SetQueryParam("method", "list").
		SetResult(&certListResp).
		SetContentType("application/json").
		Get("")
	if err != nil {
		return false, fmt.Errorf("获取证书列表错误: %w", err)
	}
	// 检查证书列表响应
	if !certListResp.Success {
		return false, fmt.Errorf("获取证书列表失败")
	}
	var existCertID string
	const customLayout = "Jan 02 15:04:05 2006 MST"
	for _, certInfo := range certListResp.Data.Certificates {
		if strings.EqualFold(certInfo.Desc, certBundle.GetNoteShort()) {
			if certBundle.IsDNSNamesMatch(certInfo.Subject.SubAltName) {
				var validTill time.Time
				validTill, err = time.Parse(customLayout, certInfo.ValidTill)
				if err != nil {
					return false, fmt.Errorf("Certificate 解析过期时间失败: %w", err)
				}
				if validTill.After(time.Now()) {
					// 证书已存在且未过期
					return true, nil
				}
				existCertID = certInfo.ID
			} else {
				// 证书已存在
				return true, nil
			}
		}
	}

	// 2. 上传证书
	var certUpdateResp types.CommonResponse[types.CertificateUpdateResponse]
	form := map[string]string{
		"desc":       certBundle.GetNoteShort(),
		"as_default": as_default,
	}
	if existCertID != "" {
		form["id"] = existCertID
	}
	_, err = openapiClient.R().
		SetQueryParam("api", "SYNO.Core.Certificate").
		SetQueryParam("version", "1").
		SetQueryParam("method", "import").
		SetFormData(form).
		SetFileReader("cert", "certificate.pem", strings.NewReader(certBundle.Certificate)).
		SetFileReader("key", "private_key.pem", strings.NewReader(certBundle.PrivateKey)).
		SetFileReader("inter_cert", "ca_bundle.pem", strings.NewReader(certBundle.CertificateChain)).
		SetResult(&certUpdateResp).
		SetContentType("application/json").
		SetForceResponseContentType("application/json").
		Post("")
	if err != nil {
		return false, fmt.Errorf("上传证书错误: %w", err)
	}
	// 检查证书上传响应
	if !certUpdateResp.Success {
		return false, fmt.Errorf("上传证书失败")
	}

	return false, nil
}
