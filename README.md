# IDAPwnGuard

**IDAPwnGuard** 是基于 IDA Pro 的自动化漏洞扫描插件，帮助安全研究人员快速定位二进制中的常见漏洞和危险函数调用，并生成易读报告。

## 功能特性

- **危险函数扫描**：检测 `strcpy`、`gets`、`sprintf` 等无边界检查的函数调用。  
- **格式化字符串漏洞**：识别并标记用户可控的 `printf`、`sprintf`、`vsprintf` 等格式化函数。  
- **堆操作风险**：自动分析 `malloc`、`calloc`、`free` 等堆函数，检测双重释放与 UAF 风险。  
- **整数溢出检测**：通过常量传播分析加法、减法、乘法指令的溢出可能。  
- **系统调用风险**：标记用户可控的 `system`、`popen`、`execve` 等命令注入点。  
- **控制流劫持**：检测基于寄存器的间接 `jmp`/`call` 并判断是否来源于用户输入，实现潜在控制流劫持扫描。  
- **报告生成**：扫描完成后在 IDA 输出窗口生成汇总报告，包含所有发现的漏洞地址和风险等级。

## 安装说明

1. 将插件脚本IDAPwnGuard.py下载下来，并放入 IDA Pro 的插件目录（如 `IDA/plugins/`）。  
2. 重启 IDA Pro。  
3. 打开任意二进制后，按下 **Ctrl+Shift+V** 即可启动 **IDAPwnGuard**。

## 使用示例

1. 加载目标二进制文件（PE/ELF）。  
2. **IDAPwnGuard** 将在后台扫描并用颜色标记：  
   - **红色** (`HIGH_RISK`): 高风险漏洞，如缓冲区溢出、格式化字符串漏洞。  
   - **蓝色** (`MEDIUM_RISK`): 中风险，如边界检查不足。  
   - **青色** (`HEAP_RISK`): 堆相关风险，如双重释放。  
   - **黄色** (`INT_OVERFLOW`): 整数溢出与符号问题。  
3. 扫描结束后，在 IDA 输出窗口查看生成的扫描报告。

## 开发与贡献

- 若需新增检测模块（如 ROP gadget 扫描、深度数据流分析），可在 `init_risk_functions` 及对应扫描方法中扩展。  
- 欢迎提交 Issue 或 Pull Request 以改进 **IDAPwnGuard** 功能。

## 许可证

MIT License © 2025
