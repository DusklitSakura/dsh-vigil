/**
 * @module dsh-vigil/audit/narrative
 *
 * Chinese risk narratives and shared text helpers for the static auditor.
 * Every finding carries a "这意味着：…" sentence and exactly one concrete
 * mitigation action, as required by FR-1.3.
 *
 * This module is intentionally dependency-free and side-effect-free so it can
 * also be reused by the terminal card renderer and by tests.
 */

/** Stable category order used by reports and the terminal card. */
export const CATEGORIES = [
  'credential',
  'network',
  'dynamic-code',
  'config-tamper',
  'supply-chain',
  'dsh-attack',
  'unknown',
]

/** Human labels (Chinese) for the risk categories. */
export const CATEGORY_LABELS = {
  credential: '凭证读取',
  network: '网络外发',
  'dynamic-code': '动态代码执行',
  'config-tamper': '配置篡改',
  'supply-chain': '供应链',
  'dsh-attack': 'dsh 特有攻击面',
  unknown: '未知',
}

/** Severity ranks; higher sorts first. */
export const SEVERITY_RANK = { blocker: 4, review: 3, notice: 2, info: 1 }

/** Human labels (Chinese) for severities. */
export const SEVERITY_LABELS = { blocker: '高危', review: '可疑', notice: '提示', info: '信息' }

/** Attribution stamped on every built-in rule finding (Apache-2.0). */
export const RULE_ATTRIBUTION = 'dsh-vigil builtin rules (Apache-2.0)'

/**
 * Honest disclaimer: static analysis cannot see runtime-variable behaviour.
 * Included verbatim in every report and printed by the terminal card.
 */
export const DISCLAIMER = '本报告由静态文本/正则分析生成，绝不执行被扫描插件的任何代码。静态扫描无法覆盖运行时可变行为（例如从网络动态下载后再执行的代码、由环境变量或远程配置决定的逻辑、被编码/混淆的内容），因此“未发现风险”不等于“插件安全”。请结合插件来源、签名、发布者信誉与人工复核后再决定是否安装。'

/**
 * Per-rule narratives. Placeholders like `{host}` are filled from finding vars;
 * unknown placeholders render as "（未确定）".
 *
 * @type {Record<string, { means: string, mitigation: string }>}
 */
const NARRATIVES = {
  'VG-CRED-01': {
    means: '这意味着：源码里直接写死了一个疑似密钥/令牌（{secretKind}）。任何拿到这个插件包的人都能读到它，插件运行时也可能把它发往任意位置。',
    mitigation: '立刻吊销并轮换该凭据；改为在运行时从环境变量或宿主凭据服务读取，不要把真实密钥写进源码或测试夹具。',
  },
  'VG-CRED-02': {
    means: '这意味着：插件包中包含一段私钥内容。私钥泄露等同于身份被完全接管，攻击者可用它登录服务器或解密相关流量。',
    mitigation: '从包中移除私钥并立即轮换该密钥对；改为引用用户本机受保护路径或宿主密钥服务。',
  },
  'VG-CRED-03': {
    means: '这意味着：插件会访问本机敏感凭证位置（{path}）。即使当前代码只是读取，也说明它具备窃取 SSH 私钥、npm/云凭据或环境密钥的能力。',
    mitigation: '确认访问该路径是插件功能必需；若非必需，请删除相关代码，并在安装前审查作者与发布来源。',
  },
  'VG-CRED-04': {
    means: '这意味着：插件会读取环境变量中的凭证类配置（{name}）。这类值通常包含 API Key 或访问令牌，可能被记录、缓存或外发。',
    mitigation: '确认该环境变量属于插件自身配置；不要复用高权限令牌，必要时为插件单独签发最小权限凭据。',
  },
  'VG-CRED-06': {
    means: '这意味着：文件里既读取了凭证路径（{path}），又向外部地址（{host}）发起请求。两者同时出现，构成"读凭证并外发"的完整链路。',
    mitigation: '拒绝安装；确认插件没有需要读取本机凭证的功能，若确有需要应改为由用户显式授权的最小接口。',
  },
  'VG-CRED-07': {
    means: '这意味着：文件里既读取了凭证类环境变量（{name}），又向外部地址（{host}）发起请求。环境变量常放 API key，外发即泄露。',
    mitigation: '拒绝安装；确认环境变量读取与网络请求是否属于同一功能路径，必要时要求作者移除。',
  },  'VG-CRED-05': {
    means: '这意味着：插件会对本机凭证文件（{path}）执行删除或覆盖类操作（{op}）。密钥只有一份，这类操作不可逆，且通常是为了抹掉痕迹或阻断后续登录。',
    mitigation: '拒绝安装；确需使用时先在隔离环境验证并用备份恢复，不要让它碰到真实的 ~/.ssh、~/.aws、~/.dsh 凭据。',
  },
  'VG-NET-01': {
    means: '这意味着：插件会向非白名单主机（{host}）发起网络请求。插件可以把本机文件、会话内容或凭证发送到该地址。',
    mitigation: '确认该主机是插件功能必需且由可信方控制；若无法确认，请阻止安装或在网络层限制该域名的出站访问。',
  },
  'VG-NET-02': {
    means: '这意味着：插件会向已知的一次性/回传类端点（{host}）发送数据。这类服务常用于把窃取内容快速传走且难以追溯。',
    mitigation: '视为高风险：除非你明确知道该端点的用途，否则拒绝安装并联系插件作者确认。',
  },
  'VG-NET-03': {
    means: '这意味着：插件直接向裸 IP 地址（{host}）发起网络连接，绕过了域名与证书体系，常见于隐蔽回传或 C2 通信。',
    mitigation: '拒绝安装；如确属内网工具，请核实该 IP 归属并改为受控域名 + TLS。',
  },
  'VG-NET-04': {
    means: '这意味着：插件存在网络外发调用（{api}），但目标地址无法从静态代码中确定。实际目标可能由配置、环境变量或运行时计算得出。',
    mitigation: '在隔离环境中运行并抓包确认目标；审查该插件配置项中所有可改变 URL 的字段。',
  },
  'VG-SUP-10': {
    means: '这意味着：插件声明的 DSH 版本要求（{field} = {spec}）不包含当前运行的 {have}。装上去以后要么加载失败，要么行为与作者验证过的版本不一致。',
    mitigation: '先向作者确认支持的 DSH 版本；不要为了装上而改动宿主版本要求，升级或换用匹配的插件版本。',
  },
  'VG-SUP-11': {
    means: '这意味着：代码 import 了 {name}，但 package.json 的依赖里没有它。干净安装时它可能根本不存在（只靠传递依赖碰巧能跑），升级或换包管理器就会炸。',
    mitigation: '要求作者把该依赖写进 dependencies；不要依赖传递依赖的偶然提升。',
  },
  'VG-SUP-12': {
    means: '这意味着：当前版本命中已知漏洞 {id}（{summary}）。攻击者可用现成的公开利用方式，不需要插件作者再犯错。',
    mitigation: '升级到修复版本；暂时无法升级时，确认该漏洞的影响面并在隔离环境使用。',
  },
  'VG-SUP-13': {
    means: '这意味着：清单声明的{kind}（{path}）在包内不存在。DSH 安装后会加载失败并回滚，安装过程可能已经改过 profile 文件。',
    mitigation: '核对路径拼写与发布内容是否一致（是否漏发文件、是否被 .npmignore 排除）；确认前不要安装。',
  },
  'VG-SUP-14': {
    means: '这意味着：包声明自己是 DSH 插件（存在 dsh 字段），但既没有入口文件也没有 bundle patch，宿主没有可加载的内容。',
    mitigation: '向作者确认发布内容；纯配置 bundle 应该声明 dsh.bundle.patch，否则装上也挂不载。',
  },
  'VG-DYN-12': {
    means: '这意味着：一段编码或拼接的字符串还原后是{kind}（{detail}）。明文里放这些东西会被直接看到，所以作者把它们编码起来了——这是刻意隐藏，而不是普通数据。',
    mitigation: '拒绝安装；如果作者声称是配置里的编码数据，要求给出明文与用途。',
  },
  'VG-DYN-07': {
    means: '这意味着：插件调用了 {api}。这类接口用来拿到模块系统之外的内部对象（例如直接取 fs），通常出现在需要绕过沙箱或隐藏意图的代码里。',
    mitigation: '拒绝安装或要求作者改用普通 import；确认没有“动态取模块再执行”的后续逻辑。',
  },
  'VG-DYN-08': {
    means: '这意味着：插件会改写{target}的方法或属性。同一进程里的其他插件与宿主都会受影响，常见于劫持行为或越权读取。',
    mitigation: '拒绝安装；若作者声称用于 polyfill，要求限定作用域并给出回滚路径。',
  },
  'VG-DYN-09': {
    means: '这意味着：插件一次性申请约 {size} 个元素/字节。这在加载阶段就能把宿主拖进 OOM 或长时间 GC。',
    mitigation: '确认分配上界与用途；无上限的分配应改为流式/分块处理，否则不要安装。',
  },
  'VG-INJ-08': {
    means: '这意味着：插件访问了 ctx.{member}。这些成员不在普通插件的注入面里，访问它们说明代码在尝试越权或探测宿主内部。',
    mitigation: '确认插件声明了对应的服务；用 ctx.get/services 正常注入，而不是直接摸特权成员。',
  },
  'VG-SUP-17': {
    means: '这意味着：这个包的名称声明自己是官方包，但内容哈希与已记录的不一致（期望 {expected}，实际 {actual}）。同名不等于同内容——这是被替换或篡改的信号。',
    mitigation: '不要安装；核对发布来源与版本，确认哈希变动是否来自官方发布，必要时删除本地副本重新获取。',
  },
  'VG-SUP-19': {
    means: '这意味着：package.json 声明了依赖（{names}），但当前安装目录里没有它们。运行时会直接 import 失败，或悄悄用到别处的副本。',
    mitigation: '重新执行完整安装（不要用 --no-optional 之类跳过的参数）；确认依赖没有被手工删除。',
  },  'VG-SUP-18': {
    means: '这意味着：插件声明只支持 Node {spec}，而当前运行的是 {have}。行为与作者验证过的环境不一致，可能加载失败或出现未测试的路径。',
    mitigation: '确认插件是否有兼容当前版本的新版本；不能升级时避免在生产环境使用。',
  },  'VG-SUP-16': {
    means: '这意味着：与上次扫描到的版本相比，这个版本多出了能力（{added}）。供应链攻击最常见的形态就是先用干净版本建立信任，再在升级版里加后门。',
    mitigation: '核对新增能力的来源与用途，确认是本次更新的真实需求；不确认就停在旧版本。',
  },
  'VG-SUP-15': {
    means: '这意味着：清单声明了 dsh.capabilities，但代码实际具备未声明的能力（{missing}）。声明与实现不一致，读者按清单判断权限会低估它。',
    mitigation: '要求作者补齐声明或移除多余能力；声明与实现一致之前，按代码实际能力评估风险。',
  },
  'VG-INJ-07': {
    means: '这意味着：这份指令/技能文件先要求改写既有规则（{verb}），又指向敏感动作（{action}）。DSH 会把文件内容交给模型，恶意文本可以不需要任何代码就诱导它读取或外发数据。',
    mitigation: '拒绝安装或删除该文件；若确为安全测试样例，请确认它不会被当作指令加载（例如放在普通文档目录）。',
  },
  'VG-DYN-16': {
    means: '这意味着：{detail}。它可能在加载或调用时占满 CPU/内存，把宿主拖到无响应；资源问题同样能造成可用的服务中断。',
    mitigation: '要求作者补上退出条件或限制循环次数；正则改为无嵌套量词/限制长度的写法，确认前不要安装。',
  },  'VG-DYN-15': {
    means: '这意味着：源码文本里出现了下载即执行模式（{detail}），但同一行没有可执行调用。它可能是文案/帮助文本，也可能是后续会被拼接执行的载荷。',
    mitigation: '确认这段文本的用途；如果它会被传给 shell/exec 调用，按高风险处理。',
  },  'VG-DYN-11': {
    means: '这意味着：插件会对系统关键路径（{path}）执行删除或覆盖（{op}）。这不是插件自己的文件，破坏后影响整机，且通常不可逆。',
    mitigation: '拒绝安装；确认插件没有需要改动系统目录的功能，必要时在隔离环境验证。',
  },
  'VG-DYN-13': {
    means: '这意味着：动态执行（{detail}）与网络外发（{host}）或下载即执行同时出现，等于"拿到远程代码并运行"的完整链路。',
    mitigation: '拒绝安装；动态执行不应与网络输入组合出现，要求作者改为静态导入与固定逻辑。',
  },
  'VG-DYN-14': {
    means: '这意味着：代码从远程 URL 动态导入模块（{target}）。模块内容不受包内哈希约束，等同于安装时获取并执行任意代码。',
    mitigation: '拒绝安装；动态导入只应指向包内相对路径或 node: 内建模块。',
  },  'VG-DYN-01': {
    means: '这意味着：插件使用 eval / new Function 之类的动态代码执行能力（{detail}）。它可以在运行时执行拼接出来的字符串，静态扫描无法预知其行为。',
    mitigation: '要求作者移除动态执行；如无法移除，请在隔离环境运行并重点审查所有传入动态执行的字符串来源。',
  },
  'VG-DYN-02': {
    means: '这意味着：插件具备启动子进程/执行系统命令的能力（{api}）。它可以调用任意 shell 命令，读写当前进程权限范围内的所有文件。',
    mitigation: '确认插件确实需要执行命令；检查命令参数是否来自不可信输入，必要时在受限用户或沙箱中运行。',
  },
  'VG-DYN-03': {
    means: '这意味着：插件包含“下载后执行”模式（{detail}）。这是恶意安装脚本最典型的载荷投递方式，实际执行内容完全由远端决定。',
    mitigation: '拒绝安装该插件；不要运行来源不明的安装脚本，改为从源码构建并人工审查。',
  },
  'VG-DYN-06': {
    means: '这意味着：插件把 base64/hex 编码的载荷解码后使用（{detail}）。编码常用来隐藏 URL、shell 命令或二次执行代码，正常功能很少需要这样做。',
    mitigation: '手工解码该字符串确认用途；若解出网络地址或命令执行，拒绝安装。注意：本规则只解码字面量，变量间传递的编码载荷无法静态还原。',
  },
  'VG-DYN-04': {
    means: '这意味着：插件在运行时动态加载模块（{detail}）。若加载地址来自网络或用户输入，等同于远程执行任意代码。',
    mitigation: '确认动态导入的模块来自包内固定路径；如为远程地址，立即拒绝安装。',
  },
  'VG-DYN-05': {
    means: '这意味着：插件使用 Node.js vm 模块执行动态代码（{detail}）。vm 不是安全边界，可被逃逸并访问宿主进程。',
    mitigation: '不要依赖 vm 作为隔离；要求作者改为静态实现，或使用真正的独立沙箱进程。',
  },
  'VG-CFG-01': {
    means: '这意味着：插件会写入宿主/项目配置或清单文件（{path}）。这会静默修改插件树、审批策略或项目配置，用户通常不会察觉。',
    mitigation: '确认写入目标是插件自己的文件而不是宿主配置；若是后者，要求作者改用 dsh 官方配置 API 或在文档中明确告知用户，否则拒绝安装。',
  },
  'VG-CFG-02': {
    means: '这意味着：插件会读取 dsh 配置（{path}）。配置中可能包含模型凭据、审批设置与工作区路径，读取行为本身可能用于信息收集。',
    mitigation: '确认该读取是功能必需；审查读取后的数据是否会被写入日志或发往网络。',
  },
  'VG-CFG-03': {
    means: '这意味着：插件试图修改或声明高风险权限策略（{detail}）。它可能在未经审批的情况下获得完整文件系统与命令执行权限。',
    mitigation: '拒绝安装；dsh 的 sandbox/approval/permission 设置不应由插件静默改写。',
  },
  'VG-CFG-05': {
    means: '这意味着：插件在可执行代码里声明了高风险权限（{detail}），例如申请完整文件系统/命令执行权限。声明即生效，后续操作不再经过审批边界。',
    mitigation: '拒绝安装；dsh 的 sandbox/approval/permission 设置不应由插件声明或改写，确需调整请由你自己在设置里改。',
  },
  'VG-CFG-04': {
    means: '这意味着：插件会写入 DSH_* 环境变量（{name}）。这会影响 dsh 其它插件或后续进程的行为，形成跨插件污染。',
    mitigation: '确认变量用途与作用域；要求作者不要修改宿主环境变量，改为使用插件自身配置。',
  },
  'VG-SUP-01': {
    means: '这意味着：安装包带有会在安装时自动执行的脚本（{name}），且脚本包含下载或 shell 执行。安装阶段通常没有沙箱，等于把任意命令执行权交给包作者。',
    mitigation: '不要安装；如确需使用，请在断网环境中用 --ignore-scripts 安装并人工审查脚本内容。',
  },
  'VG-SUP-02': {
    means: '这意味着：安装包带有安装生命周期脚本（{name}）。脚本内容不在静态正则扫描范围内，可能在安装时执行任意逻辑。',
    mitigation: '使用 --ignore-scripts 安装并人工审查该脚本；确认脚本只做本地构建、不访问网络。',
  },
  'VG-SUP-03': {
    means: '这意味着：依赖版本未锁定（{name} 使用 {spec}）。重新安装时可能拉取到不同版本，存在供应链投毒与行为漂移风险。',
    mitigation: '改用精确版本并提交锁文件（lockfile），定期审计依赖更新。',
  },
  'VG-SUP-04': {
    means: '这意味着：依赖通过明文 HTTP 拉取（{name} 的 {spec}）。传输内容可被中间人篡改，等同于执行未经验证的代码。',
    mitigation: '拒绝安装；要求作者改用 HTTPS 或精确版本 + 完整性校验。',
  },
  'VG-SUP-05': {
    means: '这意味着：包内存在 cordis.patch.yml，但 package.json 没有正确声明 dsh.bundle.patch 或 exports["./cordis.patch.yml"]（{detail}）。这可能让补丁被静默跳过，也可能是补丁加载路径被刻意隐藏。',
    mitigation: '核对 package.json 与补丁路径是否一致；若插件无法按官方形态加载，请不要安装。',
  },
  'VG-SUP-06': {
    means: '这意味着：包内有 cordis.patch.yml，但 package.json 没有 dsh 清单。它可能不是正规 dsh bundle，补丁内容来源不明。',
    mitigation: '向作者确认插件形态；非 dsh bundle 的补丁不应被安装。',
  },
  'VG-SUP-07': {
    means: '这意味着：package.json 缺少 name 或 version。插件来源与版本无法被可靠追踪，安装后难以审计与回滚。',
    mitigation: '只从能提供完整包元数据的来源安装插件。',
  },
  'VG-SUP-08': {
    means: '这意味着：package.json 定义了构建/测试之外的脚本（{name}: {cmd}）。这些脚本可能被手动或 CI 触发并执行任意逻辑。',
    mitigation: '审查该脚本内容；不要在不了解用途的情况下运行它。',
  },
  'VG-SUP-09': {
    means: '这意味着：package.json 无法解析（{reason}）。扫描器无法确认清单声明的权限、依赖和安装脚本，风险处于未知状态。',
    mitigation: '不要安装；请作者修复清单格式后重新审计。',
  },
  'VG-INJ-01': {
    means: '这意味着：插件补丁向 dsh 配置树插入了高权限服务/配置（{service}）。这可能接管凭据、沙箱、审批或插件管理能力，使插件获得超出其功能所需的权限。',
    mitigation: '拒绝安装；要求作者移除对高权限服务的注入，改为通过 dsh 官方扩展点申请最小能力。',
  },
  'VG-INJ-02': {
    means: '这意味着：插件补丁试图覆盖已存在配置行（{rowId}）。补丁会静默替换该行原有配置，可能改变其它插件或宿主的安全设置。',
    mitigation: '审查覆盖后的完整配置差异；正常插件应只使用 insert 新增行，不应覆盖既有行。',
  },
  'VG-INJ-03': {
    means: '这意味着：插件补丁在嵌套分组内再次插入（深层 insert）。这种写法可以改写插件树结构，影响范围难以从单条补丁看出。',
    mitigation: '展开并核对完整生成的配置树；拒绝来源不明的深层插入。',
  },
  'VG-INJ-04': {
    means: '这意味着：补丁配置中包含 !!js 表达式（可执行任意计算）。配置解析阶段就会运行代码，静态文本无法预知其行为。',
    mitigation: '拒绝安装或要求作者改为静态配置值；不要在补丁中使用 !!js。',
  },
  'VG-INJ-05': {
    means: '这意味着：补丁行无法被可靠识别（{rowId}）。它可能命中宿主中不存在或不确定的配置行，行为不可预测。',
    mitigation: '核对目标行是否存在以及被覆盖后的效果；无法确认时不要安装。',
  },
  'VG-INJ-06': {
    means: '这意味着：cordis.patch.yml 无法被静态解析（{reason}）。补丁可能包含扫描器无法识别的写法，风险处于未知状态。',
    mitigation: '人工打开补丁文件核对；不要安装无法审计的补丁。',
  },
  'VG-DSH-01': {
    means: '这意味着：插件的浏览器端代码会发起网络请求（{api}）。浏览器端能读取页面数据、本地存储和会话信息，并把这些内容发送出去。',
    mitigation: '在浏览器开发者工具中监控该插件的网络请求；确认目标域名与发送的数据内容。',
  },
  'VG-DSH-02': {
    means: '这意味着：插件浏览器端代码会访问 localStorage / cookie 等存储（{detail}）。这些位置可能保存登录令牌或用户数据。',
    mitigation: '确认插件不需要读取这些数据；如非必要，要求作者移除访问并限制插件权限。',
  },
  'VG-DSH-03': {
    means: '这意味着：插件浏览器端代码同时具备存储访问与网络外发能力（{detail}）。这是一个可能的凭据外发形状；静态扫描只能证明能力共现，不能证明两者之间存在数据流。',
    mitigation: '视为高风险：拒绝安装并在浏览器网络面板核实；不要在该 dsh profile 中启用该插件。',
  },
  'VG-DSH-07': {
    means: '这意味着：客户端代码调用了网络接口（{api}），但整个文件没有绝对远程地址，请求只可能是同源/相对路径。这是正常的前后端通信，不是外发。',
    mitigation: '一般无需处理；如果该文件本不该访问网络，再确认它的路由来源。',
  },  'VG-DSH-04': {
    means: '这意味着：插件浏览器端代码会直接操作 DOM 或注入 iframe/脚本（{detail}）。这可能劫持页面、伪造界面或执行注入代码。',
    mitigation: '审查注入内容是否来自可信静态资源；拒绝动态拼接 HTML 的插件。',
  },
  'VG-DSH-05': {
    means: '这意味着：插件声明自己以高权限模式运行（{detail}），例如 danger-full-access、审批 never 或关闭沙箱。这会让插件绕过 dsh 的人工审批防线。',
    mitigation: '拒绝安装；插件不应自行声明或改写沙箱与审批策略。',
  },
  'VG-DSH-06': {
    means: '这意味着：package.json 的 dsh.bundle.patch 指向包外路径（{path}）。它可以加载包外任意补丁文件，绕过包内容审查。',
    mitigation: '拒绝安装；要求补丁路径位于包内并纳入 npm 发布内容。',
  },
  'VG-SCAN-01': {
    means: '这意味着：目标目录不可读取（{reason}）。扫描器无法获取任何文件，不能给出可信的风险结论。',
    mitigation: '确认路径存在且当前用户有读取权限后重新扫描；在拿到结果前不要安装。',
  },
  'VG-SCAN-02': {
    means: '这意味着：有文件或目录无法读取（{reason}）。该部分内容未被审计，可能隐藏风险。',
    mitigation: '修复文件权限后重新扫描；不要忽略未审计的文件。',
  },
  'VG-SCAN-03': {
    means: '这意味着：本次扫描因限制跳过了部分文件（{detail}）。报告只覆盖已读取的文件，存在盲区。',
    mitigation: '把检查拆小：对不同子目录分别用 vigil_scan 覆盖，或人工查看被跳过的文件。扫描上限固定（单文件 512 KiB、400 个文件、深度 12），无法通过参数提高。',
  },
  'VG-SCAN-05': {
    means: '这意味着：AST 别名分析不可用（{detail}），本次只能依赖正则规则；通过变量别名调用的能力可能漏报。',
    mitigation: '确认 acorn 依赖已安装后重新扫描；若仍不可用，请把该结论当作“覆盖不完整”，不要当作“未发现风险”。',
  },
  'VG-SCAN-06': {
    means: '这意味着：本次扫描没有完整覆盖 {surfaces}。这些面里可能存在规则看不到的内容，“未发现风险”不等于这些面是干净的。',
    mitigation: '先用 vigil_scan 分别扫描这些子目录 / 修复不可读文件，再判断是否安装；不要只凭 0 高危就放行。',
  },
  'VG-SCAN-04': {
    means: '这意味着：包声明的入口位于未扫描目录（{dirs}，构建产物）。扫描器为控制开销跳过了该目录，因此“未发现风险”并不覆盖真正会运行的代码。',
    mitigation: '发布时带上源码目录，或先构建再重新扫描；只拿到构建产物时，不要仅凭本报告的 0 高危结论安装。',
  },
}

/** Fallback narrative for unknown rule ids. */
const FALLBACK_NARRATIVE = {
  means: '这意味着：扫描器在插件中命中了规则「{ruleId}」描述的可疑模式。',
  mitigation: '人工复核该处代码与调用来源；无法确认时不要安装。',
}

/**
 * Replace `{placeholder}` tokens with finding variables.
 *
 * @param {string} template
 * @param {Record<string, unknown>} [vars]
 * @returns {string}
 */
/** Whether a rule id has its own tailored narrative (not the fallback). */
export function hasNarrative(ruleId) {
  return Object.prototype.hasOwnProperty.call(NARRATIVES, ruleId)
}

export function interpolate(template, vars = {}) {
  const text = typeof template === 'string' ? template : ''
  return text.replace(/\{([a-z][a-z0-9_]*)\}/gi, (_match, key) => {
    const value = vars && Object.prototype.hasOwnProperty.call(vars, key) ? vars[key] : undefined
    if (value === undefined || value === null || value === '') return '（未确定）'
    return String(value)
  })
}

/**
 * Build the means/mitigation pair for a rule.
 *
 * @param {string} ruleId
 * @param {Record<string, unknown>} [vars]
 * @returns {{ means: string, mitigation: string }}
 */
export function buildNarrative(ruleId, vars = {}) {
  const entry = NARRATIVES[ruleId] ?? FALLBACK_NARRATIVE
  return {
    means: interpolate(entry.means, { ...vars, ruleId }),
    mitigation: interpolate(entry.mitigation, { ...vars, ruleId }),
  }
}

/**
 * Additional sentence appended when a secondary signal escalates a finding.
 *
 * @param {'credential-network'|'dynamic-network'|'env-network'|'client-exfil'} kind
 * @param {Record<string, unknown>} [vars]
 * @returns {string}
 */
export function escalationSentence(kind, vars = {}) {
  switch (kind) {
    case 'credential-network':
      return `此外，同一文件中同时存在网络外发能力（${vars.host || '目标不确定'}），凭证可能在一次调用中被直接发送到外部。`
    case 'dynamic-network':
      return `此外，同一文件还具备网络外发能力（${vars.host || '目标不确定'}），可形成“下载 → 执行”的完整链路。`
    case 'env-network':
      return `此外，同一文件存在网络外发能力（${vars.host || '目标不确定'}），读到的凭证可能被外发。`
    case 'client-exfil':
      return `此外，同一文件同时出现存储访问（${vars.storage || '本地存储/cookie'}）和网络请求（${vars.egress || '外发'}）；它们可能被组合成外传链路，但这只是静态共现，不代表数据实际流入请求，需要人工确认。`
    default:
      return ''
  }
}

/**
 * Trim evidence to the documented <= 240 character limit.
 *
 * @param {unknown} value
 * @param {number} [max]
 * @returns {string}
 */
export function truncateEvidence(value, max = 240) {
  const text = String(value ?? '').replace(/\s+/g, ' ').trim()
  if (text.length <= max) return text
  return `${text.slice(0, Math.max(0, max - 1))}…`
}

/**
 * Redact secret-looking tokens before printing evidence to a terminal/card.
 * The JSON report keeps the raw evidence for auditability; the human-facing
 * card must not echo live credentials.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function redactEvidence(value) {
  return String(value ?? '')
    .replace(/\b(?:AKIA|ASIA)[0-9A-Z]{12,}\b/g, (m) => `${m.slice(0, 4)}***`)
    .replace(/\b(?:sk-|ghp_|gho_|ghu_|ghs_|github_pat_|xox[baprs]-|AIza|glpat-)[A-Za-z0-9_-]{8,}\b/g, (m) => `${m.slice(0, 6)}***`)
    .replace(/(['"`])([A-Za-z0-9+/_=-]{24,})\1/g, (_m, quote, body) => `${quote}${body.slice(0, 4)}***${quote}`)
    .replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, 'eyJ***（JWT 已隐藏）')
}
