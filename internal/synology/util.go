package synology

import (
	"fmt"
	"net/url"
	"strings"
)

// ensureAPIPath 校验地址并确保其以 /webapi/entry.cgi 结尾。
func ensureAPIPath(baseURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", fmt.Errorf("地址无效: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("地址无效: 需包含协议和主机，例如 https://192.168.1.2:5001")
	}

	if !strings.HasSuffix(u.Path, "/webapi/entry.cgi") {
		if !strings.HasSuffix(u.Path, "/") {
			u.Path += "/"
		}
		u.Path += "webapi/entry.cgi"
	}
	return u.String(), nil
}
