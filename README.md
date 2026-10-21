# eMudhra / emSign Intermediate CA Vulnerability Audit & Remediation Tool

[![Release](https://img.shields.io/github/v/release/yuxiao1231/emsign_cert_update?color=brightgreen)](https://github.com/yuxiao1231/emsign_cert_update/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue)](#)
[![Python](https://img.shields.io/badge/Python-3.7%2B-brightgreen)](#)
[![Vulnerability](https://img.shields.io/badge/Bug-Mozilla%20Bug%202083449-red)](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)

[English](#english) | [中文说明](#chinese) | [直接下载 Release](#downloads)

---

<a name="downloads"></a>
## ⚡ 小白直接下载（免安装 Git / 免安装 Python）

如果你不想敲任何命令，直接点击下方官方 Release 链接下载：

| 适用场景 | 文件名 | 下载链接 | 使用方法 |
| :--- | :--- | :--- | :--- |
| **一键双击修复包（推荐）** | `emsign_oneclick_fix_windows.zip` | [📥 点击直接下载 ZIP](https://github.com/yuxiao1231/emsign_cert_update/releases/download/v1.0.0/emsign_oneclick_fix_windows.zip) | 下载解压后，**直接双击 `fix.bat`** 即可自动提权修复 |
| **单文件绿色版 EXE** | `emsign_remediator.exe` | [📥 点击直接下载 EXE](https://github.com/yuxiao1231/emsign_cert_update/releases/download/v1.0.0/emsign_remediator.exe) | 下载后直接双击或命令行运行 `emsign_remediator.exe --fix` |

---

<a name="chinese"></a>
## 🇨🇳 中文说明

### 🚨 事件背景：印度 CA 机构 eMudhra (emSign) 1 字节弱私钥漏洞
2026 年 10 月 17 日，安全研究社区（Mozilla Bug 2083449）踢爆了一起严重的 Web PKI 信任链事故：
印度 CA 机构 **eMudhra (旗下运营 emSign 品牌)** 在 2025 年 4 月的一次密钥生成仪式（Key Generation Ceremony）中，由于自动化脚本/HSM 封装的严重逻辑失误，导致其 G3 根证书下签发的 **8 张中间 CA（Intermediate CA）证书**，私钥有效熵只有 3 到 8 个 bit（部分私钥标量值甚至直接就是整数 `4`、`56`、`230` 等极小值）！

由于这些中间 CA 的公钥已被提交到全球公开的证书透明度（Certificate Transparency, CT）日志中，研究员与攻击者**仅需 11 毫秒**即可推导破解出完整的私钥。

#### 💥 核心危害与真实盲区
拥有中间 CA 私钥的攻击者，在实施 DNS 劫持、恶意 Wi-Fi 或 BGP 劫持时，可以**任意伪造全球任何域名（如 `api.openai.com`、Google、各大银行）的合法 TLS 证书**，无视 HTTPS 加密扒取数据、窃取 API Key。

- **为什么说大部分人的电脑其实依然不安全？**
  - **主流浏览器**（Chrome / Edge / Firefox）响应迅速，已通过内置的 CRLSet / OneCRL 阻断机制将公钥 Hash 拉黑；
  - **但开发者与系统工具是巨大的盲区！** 大部分操作系统底层（Windows CryptoAPI 未更新离线缓存）、Python 环境（`requests`/`httpx`/`certifi` 依赖静态根证书包）、`curl`、Git、Docker 容器以及 IoT 设备，**默认不会执行在线 CRL/OCSP 吊销查询**！只要本地证书包信任其 G3 根证书，伪造的证书就会被无条件放行！

---

### 🛠️ 方案与用法

#### 方案 A：Windows 小白一键修复（免任何环境）
1. 从上方下载 [emsign_oneclick_fix_windows.zip](https://github.com/yuxiao1231/emsign_cert_update/releases/download/v1.0.0/emsign_oneclick_fix_windows.zip) 解压；
2. **直接双击运行 `fix.bat`**；
3. 脚本会自动申请管理员权限（UAC），自动连接微软更新服务拉取官方最新不受信任证书列表（CTL），将全部 16 张受影响的中间证书**永久硬写入 Windows 底层 `Disallowed` 存储**，并自动检测修复 Python `certifi` 包。

#### 方案 B：运行单文件编译版 EXE
- 下载 [emsign_remediator.exe](https://github.com/yuxiao1231/emsign_cert_update/releases/download/v1.0.0/emsign_remediator.exe)：
  - **小白直接双击**：程序内置 UAC 管理员提权清单与安全签名，双击后弹出 UAC 允许即可自动检测修复，并在执行完毕后显示清晰结果，按回车键退出（绝不闪退）。
  - **命令行运行**：
    ```cmd
    emsign_remediator.exe --check   # 检查系统受影响状态
    emsign_remediator.exe --fix     # 一键自动加固与修复
    ```

> 💡 **关于浏览器与 Windows SmartScreen 提示说明**：
> 独立编译的 `.exe` 已内嵌 Windows PE 版本属性与开发者数字签名（DigiCert RFC 3161 权威时间戳）。但因开源项目未花费每年数百美元采购商业商业机构的 EV 代码签名证书，新发布的小众 `.exe` 在 Chrome 或 Windows SmartScreen 下直接下载可能触发“不常见文件/未验证发布者”安全提示。
> **完全避免该拦截提示的方法**：推荐直接下载上方的 **`emsign_oneclick_fix_windows.zip`** 压缩包，解压后双击 `fix.bat` 运行，体验最为丝滑顺畅！

#### 方案 C：Python 开发者跨平台脚本
- 任何安装了 Python 3.7+ 的环境（Windows / Linux / macOS）：
  ```bash
  python emsign_remediator.py --check   # 审计当前系统与 Python 环境
  python emsign_remediator.py --fix     # 一键自动加固
  ```

#### 方案 D：Linux / macOS / WSL
- 执行一键 Shell 脚本：
  ```bash
  sudo ./fix_linux.sh
  ```

---

<a name="english"></a>
## 🌐 English Documentation

### 🚨 Background: eMudhra / emSign 1-Byte Private Key Entropy Flaw
On October 17, 2026, a catastrophic Web PKI defect was publicly disclosed in **Mozilla Bug 2083449**:
Due to a key generation script error within Certificate Authority **eMudhra (operating under the emSign brand)**, the private keys for **eight subordinate/intermediate CA certificates** (cross-signed by eMudhra Root TLS CA - G3 and Sectigo/Comodo AAA Certificate Services) were generated with virtually zero entropy (scalar values $\le 256$, with some keys literally equal to integer `4`).

Security researchers recovered all affected private keys in approximately **11 milliseconds** straight from public Certificate Transparency (CT) logs.

### 💥 The Threat Model & Ecosystem Blind Spot
An attacker possessing these private keys can forge valid, cryptographically trusted TLS/SSL certificates for **any domain on the internet** (including LLM endpoints, banking services, and cloud providers).

While browser vendors (Google Chrome, Mozilla Firefox, Apple, Microsoft) deployed emergency blocks via OneCRL/CRLSets, **non-browser environments (Python `certifi`, `curl`, Git, Docker images, Linux distributions, IoT firmware)** do NOT perform live CRL/OCSP checking by default. Until their local trust stores are explicitly patched, they remain vulnerable to full Man-in-the-Middle (MitM) interception.

---

### 🛡️ Compromised Intermediate Certificates (16 Tracked Variants)

All 16 compromised intermediate certificates tracked by this tool:

| Name | Type | Issuer | SHA-256 Thumbprint |
| :--- | :--- | :--- | :--- |
| **EM EV TLS CA - G3B** | TLS Intermediate | emSign Root TLS CA - G3 | `F33ACD1F5D31AA81AC18C72C928446226D3D5914` |
| **EM OV CS CA - G3B** | Code Signing | Comodo AAA Certificate Services | `EE26D7AE3CC71718F6E07D7D0095076F0C158F63` |
| **EM OV CS CA - G3B** | Code Signing | emSign Root CS CA - G3 | `D33195A244046A3263FB5E0E83C6803A5B2E7BC3` |
| **EM EV TLS CA - G3C** | TLS Intermediate | emSign Root TLS CA - G3 | `C988F3D0CC1629FFC43165D6464C9B6EF73D6E48` |
| **EM DV TLS CA - G3B** | TLS Intermediate | emSign Root TLS CA - G3 | `A99B289464F3B44343270A7A1E910F02370483FE` |
| **EM DV TLS CA - G3C** | TLS Intermediate | emSign Root TLS CA - G3 | `8AD23BC78845D6FAAE1D534BAC89F0E36BA55A11` |
| **EM EV TLS CA - G3C** | TLS Intermediate | Comodo AAA Certificate Services | `8588708E875A1F8AA83524F3559080F7E17068C7` |
| **EM OV CS CA - G3C** | Code Signing | Comodo AAA Certificate Services | `7FDE64753A957B98F172FD2AB0D922551909C7BA` |
| **EM OV TLS CA - G3C** | TLS Intermediate | emSign Root TLS CA - G3 | `7FCC31AAB874CE6C8EE8584F54CFD08646B54117` |
| **EM OV TLS CA - G3B** | TLS Intermediate | emSign Root TLS CA - G3 | `5F014E0DB3BB8F950E0598AB280846D383FC57BE` |
| **EM OV TLS CA - G3B** | TLS Intermediate | Comodo AAA Certificate Services | `5DFA19197D1C1CF629AF7C0CD865543C5050227C` |
| **EM DV TLS CA - G3C** | TLS Intermediate | Comodo AAA Certificate Services | `4B0944C14F8C2CCBA4E4F32104AD920FA15EE331` |
| **EM OV TLS CA - G3C** | TLS Intermediate | Comodo AAA Certificate Services | `305FC1E253DCAB71B95D4995DAE3CB09D562F22A` |
| **EM OV CS CA - G3C** | Code Signing | emSign Root CS CA - G3 | `1F4A5D178F8B6A8EF0F6784155BD5FEA91158B12` |
| **EM EV TLS CA - G3B** | TLS Intermediate | Comodo AAA Certificate Services | `19069BD6533BFF93FB67C71FB3376B4EA7402C3B` |
| **EM DV TLS CA - G3B** | TLS Intermediate | Comodo AAA Certificate Services | `1396BE1372BC93DFA2A433CA964DBA91548A6E57` |

---

### 🔍 Verification Commands

#### Windows PowerShell
Verify that the certificates are present in the `Disallowed` store:
```powershell
Get-ChildItem -Path Cert:\LocalMachine\Disallowed | Where-Object { $_.Subject -like "*emudhra*" -or $_.Subject -like "*emsign*" }
```

#### Python Environment
Verify that your `certifi` package no longer contains the compromised `emSign ECC Root CA - G3` root:
```python
import certifi
with open(certifi.where(), 'r') as f:
    assert 'emsign ecc root ca - g3' not in f.read().lower()
print('Python certifi root store is clean!')
```

---

### 📜 License
Released under the [MIT License](LICENSE).