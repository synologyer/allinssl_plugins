// ALLinSSL 模块插件「群晖证书部署」的前端入口。
//
// 宿主以 ES 模块方式加载本文件并调用默认导出，传入 Vue、Naive UI 等宿主能力。
// 这里只做一件事：向工作流注册「部署到群晖」节点及其配置表单。
// 节点名需与后端 internal/workflow 中注册的节点名一致，且不能与宿主内置节点
// （apply、deploy、upload、notify 等）同名，否则宿主会按内置节点处理而注册失败。

const NODE_NAME = 'synology_deploy'
const NODE_TITLE = '部署到群晖'

// 字符串 "true"/"false" 与布尔值都按布尔处理
function toBool(value, fallback) {
  if (typeof value === 'boolean') return value
  if (typeof value === 'string' && value.trim() !== '') return value.trim().toLowerCase() === 'true'
  return fallback
}

function validate(config) {
  const url = String(config.url || '').trim()
  if (!url) return '请填写设备地址'
  if (!/^https?:\/\/[^/\s]+/i.test(url)) return '设备地址需以 http:// 或 https:// 开头，例如 https://192.168.1.2:5001'
  if (!String(config.username || '').trim()) return '请填写用户名'
  if (!config.password) return '请填写密码'
  return ''
}

function summary(config) {
  const url = String(config.url || '').trim()
  if (!url) return '未配置'
  try {
    return '部署到 ' + new URL(url).host
  } catch (error) {
    return '部署到 ' + url
  }
}

// 在工作流数据中按 ID 查找节点，返回可直接修改的原始节点对象
function findNode(node, id) {
  if (!node) return null
  if (node.id === id) return node
  const child = findNode(node.childNode, id)
  if (child) return child
  for (const branch of node.conditionNodes || []) {
    const found = findNode(branch, id)
    if (found) return found
  }
  return null
}

export default function (host) {
  const { h, defineComponent, reactive, ref, onMounted } = host.vue
  const ui = host.ui

  const DeployForm = defineComponent({
    name: 'SynologyDeployForm',
    props: {
      node: { type: Object, required: true },
      save: { type: Function, required: true },
      close: { type: Function, required: true },
    },
    setup(props) {
      const config = props.node.config || {}
      const model = reactive({
        url: config.url || '',
        username: config.username || '',
        password: config.password || '',
        cert_desc: config.cert_desc || '',
        as_default: toBool(config.as_default, false),
        skip_verify: toBool(config.skip_verify, true),
        // 与内置部署节点一致，用 1 / 0 保存
        skip: toBool(config.skip === undefined ? true : String(config.skip) === '1' || config.skip === true, true),
      })
      const error = ref('')

      // 证书来源：列出本节点之前的申请/上传/私有 CA 节点，与内置部署节点的做法一致。
      const sourceOptions = ref([])
      const source = ref((props.node.inputs && props.node.inputs[0] && props.node.inputs[0].fromNodeId) || '')
      let flowStore = null
      const hasFlow = ref(false)

      onMounted(async () => {
        try {
          const store = await host.load('components/flowChart/useStore.tsx')
          flowStore = store.useStore()
          sourceOptions.value = flowStore
            .findApplyUploadNodesUp(props.node.id)
            .map(item => ({ label: item.name, value: item.id }))
          hasFlow.value = true
          if (!sourceOptions.value.some(item => item.value === source.value)) {
            source.value = sourceOptions.value.length ? sourceOptions.value[0].value : ''
          }
        } catch (loadError) {
          // 宿主不提供工作流数据时不显示证书来源，后端改用上一个节点输出的证书。
          console.warn('[synology] 读取工作流数据失败，证书来源将使用上一个节点', loadError)
          flowStore = null
          hasFlow.value = false
        }
      })

      const saveSource = () => {
        if (!flowStore) return
        const flow = flowStore.flowData && flowStore.flowData.value
        const target = flow && findNode(flow.childNode, props.node.id)
        if (!target) return
        const option = sourceOptions.value.find(item => item.value === source.value)
        target.inputs = option ? [{ name: option.label, fromNodeId: option.value }] : []
      }

      const submit = () => {
        const next = {
          url: model.url.trim(),
          username: model.username.trim(),
          password: model.password,
          cert_desc: model.cert_desc.trim(),
          as_default: model.as_default,
          skip_verify: model.skip_verify,
          skip: model.skip ? 1 : 0,
        }
        error.value = validate(next)
        if (error.value) return
        if (flowStore && !source.value) {
          error.value = '请先在本节点之前添加申请证书或上传证书节点'
          return
        }
        saveSource()
        props.save(next)
      }

      // 说明文字用普通的次要文字显示，不占用表单项的校验提示位置（那里会显示成报错的红色）。
      const item = (label, control, hint) =>
        h(ui.NFormItem, { label }, () =>
          h('div', { style: 'width: 100%' }, [
            control,
            hint ? h('div', { style: 'margin-top: 4px; font-size: 12px; line-height: 1.5; opacity: 0.6' }, hint) : null,
          ]),
        )

      return () =>
        h('div', { class: 'synology-deploy-form' }, [
          h(ui.NForm, { labelPlacement: 'left', labelWidth: 120, model }, () => [
            hasFlow.value
              ? item(
                  '证书来源',
                  h(ui.NSelect, {
                    value: source.value || null,
                    options: sourceOptions.value,
                    placeholder: '请选择提供证书的节点',
                    'onUpdate:value': value => (source.value = value || ''),
                  }),
                )
              : null,
            item(
              '设备地址',
              h(ui.NInput, {
                value: model.url,
                placeholder: 'https://192.168.1.2:5001',
                'onUpdate:value': value => (model.url = value),
              }),
              '以 http:// 或 https:// 开头。不写端口时使用默认端口（http 为 80，https 为 443）；直连设备时 NAS 一般是 5001，路由器是 8001',
            ),
            item(
              '用户名',
              h(ui.NInput, {
                value: model.username,
                placeholder: '具有管理员权限的群晖账号',
                'onUpdate:value': value => (model.username = value),
              }),
            ),
            item(
              '密码',
              h(ui.NInput, {
                value: model.password,
                type: 'password',
                showPasswordOn: 'click',
                placeholder: '群晖账号密码',
                inputProps: { autocomplete: 'new-password' },
                'onUpdate:value': value => (model.password = value),
              }),
              '账号不能开启两步验证',
            ),
            item(
              '证书描述',
              h(ui.NInput, {
                value: model.cert_desc,
                placeholder: '留空则为 allinssl-证书的第一个域名',
                'onUpdate:value': value => (model.cert_desc = value),
              }),
              '证书在群晖中显示的描述。每次部署都会按这个描述找到原证书并原位替换，原证书的默认状态和服务绑定保持不变',
            ),
            item(
              '设为默认证书',
              h(ui.NSwitch, { value: model.as_default, 'onUpdate:value': value => (model.as_default = value) }),
              '关闭时保持群晖里原有的设置：被替换的证书原本是默认证书的，替换后仍是默认证书',
            ),
            item(
              '跳过证书校验',
              h(ui.NSwitch, { value: model.skip_verify, 'onUpdate:value': value => (model.skip_verify = value) }),
              '设备使用自签名证书或通过 IP 访问时需要开启',
            ),
            item(
              '重复部署',
              h(
                ui.NSwitch,
                { value: model.skip, 'onUpdate:value': value => (model.skip = value) },
                { checked: () => '跳过', unchecked: () => '不跳过' },
              ),
              '当与上次部署的证书相同且上次部署成功时是否跳过。选择不跳过时，每次执行都会重新上传并替换',
            ),
          ]),
          error.value
            ? h(ui.NAlert, { type: 'error', showIcon: false, style: 'margin-bottom: 16px' }, () => error.value)
            : null,
          h(ui.NSpace, { justify: 'end' }, () => [
            h(ui.NButton, { onClick: () => props.close() }, () => '取消'),
            h(ui.NButton, { type: 'primary', onClick: submit }, () => '保存'),
          ]),
        ])
    },
  })

  host.workflow.addNode({
    name: NODE_NAME,
    title: NODE_TITLE,
    icon: 'deploy',
    order: 6,
    defaultConfig: { url: '', username: '', password: '', cert_desc: '', as_default: false, skip_verify: true, skip: 1 },
    summary,
    validate,
    form: DeployForm,
  })

  // 本插件不新增页面、菜单或插槽，无需导出组件。
  return {}
}
