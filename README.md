# XosZhTool

XOS-Toolkit 界面汉化工具：扫描 exe 内 BAML 文本记录，按翻译表等长覆写（中文 UTF-8 + 空格填充），生成 `*.zh.exe`。零依赖，系统自带 csc 即可编译。

## 使用

1. 将 `XOS-Toolkit.exe` 放到工具同目录
2. 双击 `XosZhTool.exe`，或命令行运行 `XosZhTool.exe --auto`
3. 生成 `XOS-Toolkit.zh.exe`，替换原程序即可

翻译表：`zh_map.tsv`（界面文本）/ `us_map.tsv`（运行时字符串，换行写作 `|`），格式 `英文<TAB>中文`，改表重跑即可，无需重编译。

## 编译

```
csc /nologo /codepage:65001 /target:winexe /win32icon:xoszhtool.ico /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll XosZhTool.cs
```

仅供个人学习与本地化研究使用。
