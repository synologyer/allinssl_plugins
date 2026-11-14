// Package module 实现 ALLinSSL 模块插件协议（协议版本 1）的插件端。
//
// 宿主（ALLinSSL）启动插件后端进程时通过环境变量下发凭据，插件监听本机回环
// 端口并把地址写到标准输出；之后宿主通过 HTTP 调用插件：
//
//   - POST /invoke        执行工作流节点等扩展点
//   - GET  /api/workflow  读取插件注册的工作流节点
//
// 宿主关闭插件的标准输入时，插件退出。
package module

// Protocol 是本包实现的模块协议版本。
const Protocol = 1

// 宿主启动插件进程时设置的环境变量。
const (
	EnvToken = "ALLINSSL_MODULE_TOKEN" // 宿主与插件互相调用使用的凭据
	EnvID    = "ALLINSSL_MODULE_ID"    // 模块标识，与目录名一致
	EnvData  = "ALLINSSL_MODULE_DATA"  // 模块专属数据目录
)

// Invoke 是宿主发给 /invoke 的调用请求。
type Invoke struct {
	Kind    string         `json:"kind"`    // 扩展类型，例如 workflow
	Target  string         `json:"target"`  // 扩展目标，工作流节点为 plugin:<模块>:<节点>
	Stage   string         `json:"stage"`   // before / replace / after
	Handler string         `json:"handler"` // 插件注册的处理器名称
	Params  map[string]any `json:"params,omitempty"`
	Result  any            `json:"result,omitempty"`
	Error   string         `json:"error,omitempty"`
}

// Reply 是插件对 /invoke 的响应，Error 非空表示执行失败。
type Reply struct {
	Params map[string]any `json:"params,omitempty"`
	Result any            `json:"result,omitempty"`
	Error  string         `json:"error,omitempty"`
}

// WorkflowRegistration 是 /api/workflow 返回的工作流节点注册表。
type WorkflowRegistration struct {
	Nodes     []WorkflowNode    `json:"nodes,omitempty"`
	Overrides map[string]string `json:"overrides,omitempty"`
}

// WorkflowNode 声明一个工作流节点及其处理器。
type WorkflowNode struct {
	Name    string `json:"name"`
	Handler string `json:"handler"`
	Title   string `json:"title,omitempty"`
	Order   int    `json:"order,omitempty"`
}
