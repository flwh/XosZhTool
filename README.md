# XosZhTool

XOS-Toolkit 界面汉化工具 —— 零依赖单文件，双击即用。

## 特性

- **零依赖**：仅用系统自带 `csc.exe` 编译，无需安装 .NET SDK 或运行库
- **安全覆写**：实时扫描 exe 内 BAML 文本记录，白名单组过滤 + 覆写前结构复核；长度前缀与偏移零改动，输出与原文件等长（中文 UTF-8 + 空格填充）
- **翻译表驱动**：`zh_map.tsv`（BAML 界面文本，435 键）+ `us_map.tsv`（运行时字符串覆写白名单），改表即生效，无需重编译工具
- **黑名单兜底**：路由 key / 数据键 / 比较值等被代码依赖的字符串绝不覆写 —— 安全翻译第一
- 双击即用的 GUI（无边框自绘窗体），另提供 `--auto` 无窗口模式（日志写 `XosZhTool.log`）

## 使用

1. 将 `XOS-Toolkit.exe` 放到本工具同目录
2. 双击 `XosZhTool.exe` 生成；或命令行静默：`XosZhTool.exe --auto`
3. 产出 `XOS-Toolkit.zh.exe`，替换原程序即可

## 自定义翻译

编辑 `zh_map.tsv`（UTF-8，格式 `英文<TAB>中文`），保存后重新生成即可。
`us_map.tsv` 同格式，用于程序运行时字符串（#US 元数据堆，UTF-16 等长填充）；文本内换行写作 `|`。

## 从源码编译

```
csc /nologo /codepage:65001 /target:winexe /win32icon:xoszhtool.ico /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll XosZhTool.cs
```

## 文件说明

| 文件 | 说明 |
| --- | --- |
| XosZhTool.cs | 全部源码（单文件） |
| XosZhTool.exe | 编译好的工具 |
| zh_map.tsv | BAML 界面文本翻译表（435 键） |
| us_map.tsv | 运行时字符串（#US 堆）覆写白名单 |
| xoszhtool.ico | 工具图标 |

## 已知边界

- XOS-Toolkit 原版经 ConfuserEx 混淆，运行时字符串（部分弹窗长文、OK / Yes / No 按钮等）被加密进常量表，不在汉化范围
- 「About→关于」因中文 UTF-8 字节数超过原串预算（5B）保持英文；`us_map.tsv` 的 #US 覆写对未混淆程序集生效

仅供个人学习与本地化研究使用。
