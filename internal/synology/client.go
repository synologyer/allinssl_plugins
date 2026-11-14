// Package synology 通过群晖 Web API 向 DSM（NAS）和 SRM（路由器）部署证书。
package synology

import (
	"context"
	"crypto/tls"
	"fmt"

	"resty.dev/v3"
)

// Client 是群晖 Web API 客户端，DSM 与 SRM 使用同一套接口。
type Client struct {
	*resty.Client
	username string
	password string
	token    string // SynoToken
	sid      string // 会话标识，用于登出
}

// NewClient 创建客户端，baseURL 需包含协议和端口，例如 https://192.168.1.2:5001
// https://kb.synology.cn/zh-cn/DG/DSM_Login_Web_API_Guide/1
func NewClient(baseURL, username, password string, skipVerify bool) (*Client, error) {
	apiURL, err := ensureAPIPath(baseURL)
	if err != nil {
		return nil, err
	}

	client := resty.New().SetBaseURL(apiURL)
	client.SetResponseMiddlewares(
		ensure2xxResponseMiddleware,       // 先判断状态码
		resty.AutoParseResponseMiddleware, // 再解析响应
	)
	if skipVerify {
		client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	}

	return &Client{Client: client, username: username, password: password}, nil
}

// Login 登录并保存会话令牌，后续请求自动携带。
// https://kb.synology.cn/zh-cn/DG/DSM_Login_Web_API_Guide/2
func (c *Client) Login(ctx context.Context) error {
	if c.token != "" {
		return nil
	}
	var resp commonResponse[loginData]
	_, err := c.R().
		SetContext(ctx).
		SetQueryParam("api", "SYNO.API.Auth").
		SetQueryParam("version", "6").
		SetQueryParam("method", "login").
		SetQueryParam("account", c.username).
		SetQueryParam("passwd", c.password).
		SetQueryParam("enable_syno_token", "yes").
		SetResult(&resp).
		Get("")
	if err != nil {
		return fmt.Errorf("登录请求失败: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("登录失败%s，请检查用户名、密码以及是否开启了两步验证", errorCode(resp.Error.Code))
	}
	if resp.Data.Synotoken == "" {
		return fmt.Errorf("登录失败: 未返回令牌")
	}
	c.token = resp.Data.Synotoken
	c.sid = resp.Data.Sid
	c.SetHeader("X-SYNO-TOKEN", c.token)
	return nil
}

// Logout 登出当前会话，未登录时不做任何事。
func (c *Client) Logout(ctx context.Context) error {
	if c.sid == "" {
		return nil
	}
	var resp commonResponse[struct{}]
	_, err := c.R().
		SetContext(ctx).
		SetQueryParam("api", "SYNO.API.Auth").
		SetQueryParam("version", "6").
		SetQueryParam("method", "logout").
		SetQueryParam("_sid", c.sid).
		SetResult(&resp).
		Get("")
	if err != nil {
		return fmt.Errorf("登出请求失败: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("登出失败%s", errorCode(resp.Error.Code))
	}
	c.token = ""
	c.sid = ""
	return nil
}

func errorCode(code int) string {
	if code == 0 {
		return ""
	}
	return fmt.Sprintf("（错误码 %d）", code)
}

// ensure2xxResponseMiddleware 确保响应状态码为 2xx
func ensure2xxResponseMiddleware(_ *resty.Client, resp *resty.Response) error {
	if !resp.IsSuccess() {
		return fmt.Errorf("状态码 %d, 响应: %s", resp.StatusCode(), resp.String())
	}
	return nil
}
