package synology

// commonResponse 是群晖 Web API 的通用响应结构。
type commonResponse[T any] struct {
	Data    T    `json:"data,omitempty"`
	Success bool `json:"success"`
	Error   struct {
		Code int `json:"code"`
	} `json:"error"`
}

// loginData 登录返回数据
// https://kb.synology.cn/zh-cn/DG/DSM_Login_Web_API_Guide/2
type loginData struct {
	Sid       string `json:"sid"`       // 会话标识
	Synotoken string `json:"synotoken"` // CSRF 令牌
}

// certificateList 证书列表返回数据
type certificateList struct {
	Certificates []struct {
		ID      string `json:"id"`   // 证书ID
		Desc    string `json:"desc"` // 证书描述
		Subject struct {
			SubAltName []string `json:"sub_alt_name"` // 证书域名
		} `json:"subject"`
		ValidTill string `json:"valid_till"` // 证书过期时间
	} `json:"certificates"`
}

// certificateImport 证书导入返回数据
type certificateImport struct {
	ID string `json:"id"`
}
