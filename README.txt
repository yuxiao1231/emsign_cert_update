========================================================================
   eMudhra / emSign 证书熵漏洞 一键修复与安全加固工具包 (Windows)
   Tracking: Mozilla Bug 2083449 | Zero-Dependency One-Click Fix
   Author: Yuxiao Zhang (@yuxiao1231) & Zhang Qishuang
========================================================================

【小白使用指南（只需一步）】
推荐直接双击运行包内的 `fix.bat`：
1. 鼠标双击 `fix.bat`。
2. 弹出 Windows 用户账户控制（UAC）提示时，点击“是(Yes)”允许管理员权限。
3. 窗口将自动同步微软官方 Disallowed CTL 黑名单，阻断全部 16 张弱私钥中级证书。
4. 看到绿色“All 16 compromised intermediate certificates are verified BLOCKED”后，按回车键退出即可！

【也可以直接双击 emsign_remediator.exe】
如果您喜欢单文件，也可以直接双击 `bin/emsign_remediator.exe`。
- 本程序已内嵌 UAC 提权清单与数字签名，并在执行完毕后停留显示结果，绝不闪退。
- 如果浏览器下载单一 exe 时提示“未常见下载”，这是因为开源项目未采购每年数千美元的商业 EV 证书。下载 zip 压缩包运行 fix.bat 可以完全避免该提示。

【包含文件】
- fix.bat                          : 一键启动批处理脚本（推荐）
- scripts/fix_windows.ps1          : PowerShell 核心修复加固脚本
- data/compromised_intermediates.json : 受影响的全部 16 张中间证书指纹数据库
- bin/emsign_remediator.exe        : 独立编译的完整检测加固程序（已签名）
