# zcode-command-reviewer

**TL;DR (English)** — A permission-hook for [ZCode](https://zcode.z.ai) that gives Bash commands a
middle tier between *"approve every command by hand"* and *"full access"*:
a local ruleset (deny / human-only / read-only allow / trusted SSH hosts), a cheap-model reviewer
for everything in between, fail-closed on every error, and a learned prefix-rule layer so repeated
commands stop costing anything. Single Python file, no dependencies, no app patching.
Read-only in the sense that it never touches ZCode itself — it plugs into the documented hook
extension point (`~/.zcode/cli/config.json`).

---

ZCode 的命令审查 hook：在「逐条审批」和「完全访问」之间补上一档。

- 单个 Python 文件（`review-command.py`），**无第三方依赖**，不改 ZCode 本体
- 五层判决 + 学习式前缀规则，一切异常都退回人工（fail-closed）
- 适配 ZCode 3.11.2（macOS 验证；hook 协议是 Claude Code 兼容的，理论跨平台）

## 为什么需要它

ZCode 自带两档：一条条点「允许」，或者 `yolo`（完全访问）。前者会审批疲劳——用户疲劳之后
要么切到完全访问，要么写一条过宽的允许规则；后者等于没有任何把关。

业界（Codex / Claude Code）的做法是三层：**OS 沙箱定边界 → 确定性规则 → 模型审查（只在越界时）**。
本项目做后两层：ZCode 的 Bash 目前没有 OS 级沙箱（`seatbelt`/`bwrap`/`sandbox-exec` 在
`zcode.cjs` 里 0 命中），所以用「确定性规则 + 便宜模型审查」把绝大多数命令挡在弹窗之外。

## 安装

### 1. 放文件

```bash
mkdir -p ~/.zcode/hooks
cp review-command.py policy.json ~/.zcode/hooks/
```

### 2. 注册 hook

把下面这段**合并**进 `~/.zcode/cli/config.json`（该文件可能已存有 `mcp` / `plugins` 等其他键，
不要整体覆盖）。也可以用 `examples/hook-config.json`：

```json
{
  "hooks": {
    "enabled": true,
    "timeoutMs": 20000,
    "maxOutputBytes": 32768,
    "events": {
      "PermissionRequest": [
        {
          "matcher": "Bash",
          "hooks": [
            {
              "type": "process",
              "command": "/usr/bin/python3",
              "args": ["/Users/you/.zcode/hooks/review-command.py"],
              "timeoutMs": 18000,
              "statusMessage": "自动审查命令"
            }
          ]
        }
      ]
    }
  }
}
```

注意：

- **`hooks.enabled` 必须为 `true`** —— 配置文件里的 hook 默认不运行。
- `matcher` 是**大小写敏感的正则**，写错会静默失效（`bash` 匹配不到 `Bash`）。
- 改动这个文件**需要重启 ZCode** 才生效；改 `policy.json` 不需要（脚本每次调用都重新读）。

### 3. 确认生效

在 `edit` / `build` 模式的项目里随便跑一条命令，然后：

```bash
ls -la ~/.zcode/hooks/invocations.jsonl   # 文件出现且时间对得上 = hook 已被调用
```

> ⚠️ **`yolo` 模式下 hook 完全不会被调用** —— yolo 在权限判定链里最靠前就短路放行了，
> 不产生审批请求。想让它生效，项目权限模式要是 `edit` 或 `build`。

## 判决流程

```
本地 deny ──→ 强制人工 ──→ 只读白名单 ──→ 可信远端 ──→ 已学规则 ──→ 模型审查 ──→ 人工弹窗
 直接拒      不送模型      本地放行        本地放行      本地放行      带上下文       fail-closed
```

每层只在上一层没结论时才轮到。任何内部异常（读写失败、JSON 解析失败、模型超时）
都返回空输出 + exit 0，**绝不会因为脚本自身出错而卡住会话**，也不会误放行。

### 实现机制

ZCode 的审批点是个赛跑（`racePermissionResponders`）：

```js
let l = (c,d) => { i || ((i=!0), c(), d.abort()) };      // 只 settle 一次，输家被 abort
e.requestBroker(r.signal).then(c => l(() => s({result:c, source:"broker"}), t));  // 人工弹窗
e.runHooks(t.signal).then(c => { c !== void 0 && l(() => s({result:c, source:"hook"}), r) });
```

hook 先给出决策 → 人工弹窗被 abort，用户不用点；hook 不输出 → 正常弹窗。
所以这个 hook **只可能减少弹窗或直接拒绝**，不会自己放行它没明确允许的东西。

## 策略（`policy.json`）

| 段 | 作用 |
| --- | --- |
| `deny` | 直接拒绝，不弹窗，理由回给模型。删根/家/通配、提权、写裸设备、格式化磁盘、关机重启、fork bomb、`chmod -R 777 /`、`curl\|sh`、`git push --force`/`reset --hard`/`clean -fdx`、写系统目录、写凭据目录、改 shell 启动文件、关系统安全机制、改固件启动项 |
| `sensitive` | 强制人工确认**且不交给模型**（模型判断不了某个路径是不是机密）：`.ssh`/`.gnupg`/`.aws`/`.kube`、SSH 私钥、`credentials.json` 类文件、`.netrc`/`.npmrc`/`.pypirc`/`.git-credentials`、钥匙串、`.env` |
| `always_ask` | 强制人工：**不可逆但合法、且日常不常见**的动作——发布到包/镜像仓库、重写 git 历史、清空数据库对象、装开机/定时持久化任务、改包管理器源、改网络/防火墙、强杀全部进程、清 shell 历史。判据是「罕见 + 难以撤回」，别塞日常高频操作 |
| `allow` | 只读白名单，命中即本地放行（0 token / 0 延迟）。判据是命令**形状**：按未加引号的 `\|` `\|\|` `&&` `;` 换行切段，每一段都要命中；整条不得含未加引号的 `>` `<` `&` 或命令替换（`2>&1`、`>/dev/null` 先被消掉）；引号内的 `\|` `>` `&` 算字面量。白名单**大小写敏感**，三类拦截规则大小写不敏感 |
| `trusted_remote` | 把文件/命令送到**你自己的服务器**：`scp`/`sftp`/`rsync` 的所有远端目标都在 `hosts` 里才放行；`ssh` 要求主机可信**且远端命令本身通过本地检查**（deny 仍优先）。陌生主机照旧走模型 |
| `learn` | 学习式前缀规则，见下 |
| `model_review` | 模型审查配置，见下 |

## 模型审查

本地规则判不准时，把命令交给一个便宜的模型看；模型说 ALLOW 才放行，否则退回人工。

- **带上下文**：从会话库取最近的真实用户发言（只认运行时标注的 `semantics.origin == "real_user"`）
  作为「授权依据」，放进提示词的 **TRUSTED** 段；待审命令与 cwd 放进 **UNTRUSTED** 段并明确告知
  可能被污染、不得当作授权。**刻意不取助手输出、更不取工具输出**——那些可能已被仓库文件或网页
  内容污染，放进去等于给 prompt injection 开门（Claude Code 的分类器也是直接剥离工具结果）。
- **输出带理由**：`ALLOW`，或 `ASK - <不超过 15 字的理由>`。理由写进 `decisions.jsonl` 的
  `model_reason` 并进 `--stats`，所以「模型为什么判 ASK」有据可查。
- **省 token**：关思考（`reasoning_effort: low`）、`max_tokens` 适中、命中缓存 0 token
  （缓存键 = cwd + 命令 + 用户上下文哈希）。
- **熔断**：**只在接口连续失败时**熔断（默认 3 次，暂停 120s），避免每条命令都卡超时。
  注意这与 Codex/Claude 的语义**不同**——它们的熔断条件是「审查者连续拒绝」，那意味着 agent
  在反复撞墙；而本项目的模型从不拒绝，只会说「需人工」，那只是把决定交给用户确认，不构成异常。
  拿它当熔断条件反而会把本来能放行的命令推回人工（这一点在对抗性回归里被实测抓到过）。
  想恢复成按 ask 熔断，把 `breaker_consecutive_ask` 设成正整数。

### 实测踩过的坑（都是真实网关行为）

1. **不带 User-Agent 会被 Cloudflare 拦成 403**（`error code: 1010`）。必须带 `user-agent`。
2. **`reasoning_effort` 的合法值只有 `low|medium|high|xhigh|max`**，没有 `none`/`minimal`。
3. **`thinking:{type:"disabled"}` 与 `chat_template_kwargs.enable_thinking=false` 在部分网关无效**。
   推理模型可能强制思考：`max_tokens` 太小会被思考吃光、`content` 返回空 → 于是 fail-closed 误判 ASK。
   选型时优先挑「`reasoning_effort: low` 能把 reasoning 压到 0」的模型。
4. 提示词要用**风险导向**（默认放行、只在有实质危害时拦），不能用证明导向——
   写成「只在可证明只读时 ALLOW」的话，模型会把 `python3 - <<PY` 一律判 ASK，等于没接模型。

## 学习式前缀规则

ZCode 自带的「总是允许」记的是**整条命令原文**，所以 `cargo test` 放行过之后，
`cargo test --lib` 还会再问。本层把**模型判过 ALLOW** 的命令沉淀成 **token 前缀规则**
（仿 Codex 的 `prefix_rule`）：`cargo test` 一旦学成，`cargo test --lib --release` 也直接放行。

保守约束（`test-learn.py` 有 30 条用例守着）：

| 约束 | 说明 |
| --- | --- |
| 只从模型 ALLOW 学 | 人工批准**不算**——那可能只是用户这一次愿意放行 |
| 只学简单片段 | 含重定向 / 命令替换 / 通配 / 后台符的命令整条不学 |
| 只学白名单工具头 | 构建/测试/lint 类（`cargo` `go` `git` `pytest` `make` `npm run`…）。**解释器（python/node/sh）、安装、删除、网络外发类永不在名单里** |
| token 级禁词 | 出现 `install` `add` `push` `publish` `rm` `clean` `-i` `--force` `-g` `sudo` 等就不学 |
| 见 N 次才升级 | 默认 2 次，一次性的偶然放行不会变成长期策略 |
| TTL + 上限 | 默认 30 天过期、最多 200 条 |

规则存在 `learned-rules.json`（与手写的 `policy.json` 分开，便于单独清理）。
deny 永远优先于学到的规则：`cargo test` 学成后，`cargo test && rm -rf /` 依然被拒。

## 命令

```bash
cd ~/.zcode/hooks
python3 review-command.py --rules              # 打印当前生效的完整策略
python3 review-command.py --learned            # 已学规则 + 待升级候选
python3 review-command.py --forget 'cargo test'  # 删除某条规则（含同名候选）
python3 review-command.py --stats              # 命中率 + 退回人工的原因分布
python3 review-command.py --test '<命令>'      # 离线试跑本地规则
python3 review-command.py --review '<命令>'    # 连模型审查一起试跑
```

## 测试

```bash
python3 test-policy.py   # 116 条静态规则用例
python3 test-learn.py    # 30 条学习逻辑用例（用临时文件，不动真实规则）
```

回归覆盖了对抗性用例，包括：变量藏起来的根删除（`R=/; rm -rf $R`）、`base64 -d | sh` 编码绕过、
`kill -9 -1`、重定向清空文件、以及「上传到陌生主机仍要问」「ssh 内层提权被拦」等。

## 已知限制（重要）

1. **这不是安全边界。** 两个厂商都明确写过：模型审查是「约束善意 agent 的便利机制」，
   而不是对抗恶意代码的屏障。公开演示过的绕过路径（PromptArmor 对 Codex approve-for-me：
   仓库 issue 里的隐藏注入 → agent 请求提权安装恶意包 → 审查器批准 → postinstall 在沙箱外执行）
   对本项目同样适用。**真正执行边界的层是 OS 沙箱，而 ZCode 目前没有。**
2. **只覆盖 Bash**。hook 的 matcher 只注册了 `Bash`；`Write`/`Edit` 工具不走这条线，
   文件写入由权限模式直接接受。
3. **通知无法被这一步消掉**。通知是在权限请求**产生时**发出的，而 hook 是在那之后才给出放行
   （两者赛跑）。所以自动放行的命令仍可能闪一下通知。要彻底不闪，得把放行结果写进 ZCode
   自己的项目规则表（hook 决策里的 `permissionUpdates: [{type:"addRules", ...}]`）。
4. **写进 ZCode 规则表时不要用前缀语法**。`matchesRuleContent` 支持 `"cmd:*"` 前缀，但 ZCode
   **不拆分复合命令**（`ruleSubjects()` 对 Bash 直接取整个 command 字符串），所以 `cargo test:*`
   会连带放行 `cargo test && rm -rf ~/Documents`，而且那条路径上本地 deny 层完全不参与。
   要写就写**精确匹配**（`ruleContent` 不含 `*`）。
5. **命令正文会发到你配置的模型网关**。这是模型审查的固有代价；不接受就把
   `model_review.enabled` 设为 `false`，退回纯本地规则。
6. **hook 自身可被改**。`~/.zcode/hooks/` 在 agent 的可写范围内，理论上可以改掉这个守卫。
   策略里已加一条拦截对 hooks 目录的写入，但那只是提高门槛，不是硬边界。

## 设计参考

- Codex `approvals_reviewer = "auto_review"`（Approve for me）：审查器是一个独立子会话，
  输入是精简 transcript + 待审动作 JSON，按可信度标注证据，输出 `{risk_level, outcome, rationale}`，
  并有拒绝熔断器
- Codex `prefix_rule(pattern=["cargo","test"], decision="allow")`：本项目学习层的来源
- Claude Code 的 `auto` 分类器：**剥离工具结果**、连续拒绝后暂停 auto 模式、fail-closed
- Claude Code 的规则语义：deny > ask > allow，复合命令逐段匹配（本项目的白名单沿用同一思路）
- 社区同类项目：`nah`（纯确定性分类器）、`claude-smart-approval`（deny 前置 + 模型二判 + 不确定性静默）、
  `claude-remote-approver`（转发到手机，超时回退人工）

## 许可

MIT，见 `LICENSE`。
