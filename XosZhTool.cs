// XosZhTool.cs —— XOS-Toolkit.exe 汉化工具（BAML 等长覆写，GUI）
// 特性：零依赖单文件，系统自带 csc.exe 编译，双击即用；--auto 无窗口模式（日志写 XosZhTool.log）。
// 原理：实时扫描 exe 内 BAML 文本记录 -> 白名单组过滤 -> 读取 zh_map.tsv 预算校验 ->
//       以「中文 UTF-8 + 空格填充」覆写至原字节长度（长度前缀与偏移零改动）-> 输出 *.zh.exe。
// 补充：另扫 .NET 元数据 #US 堆（UTF-16 运行时字符串），按 us_map.tsv 白名单做 UTF-16 等长填充；
//       内置黑名单兜底（路由 key/数据键/比较值绝不覆写），安全翻译第一。
// 编译：
//   csc /nologo /codepage:65001 /target:winexe /win32icon:xoszhtool.ico /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll XosZhTool.cs

using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

internal static class Core
{
    private const string FallbackSrc = @"K:\vibecode\ssshss\xos\extracted\XOS-Toolkit.exe";

    // 优先取工具同目录的 XOS-Toolkit.exe（工具与源程序同目录即用），否则回退旧解包路径
    public static string DefaultSrc
    {
        get
        {
            string p = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "XOS-Toolkit.exe");
            return File.Exists(p) ? p : FallbackSrc;
        }
    }

    private sealed class Template
    {
        public readonly int Type;
        public readonly int Pre;
        public readonly int Post;
        public Template(int t, int pre, int post) { Type = t; Pre = pre; Post = post; }
    }

    // (type, pre, post) 模板表：payload = [pre][len:7bit][utf8 text][post]，size = payload + sizeBytes(自含)
    private static readonly Template[] Templates = new Template[]
    {
        new Template(0x10, 0, 0), // Text
        new Template(0x19, 0, 2), // DefAttribute
        new Template(0x05, 2, 0), // Property
        new Template(0x1F, 5, 0), // AttributeInfo
        new Template(0x20, 2, 0), // StringInfo
        new Template(0x24, 2, 2), // PropertyWithConverter
        new Template(0x34, 0, 2), // PresentationOptionsAttribute
    };

    private sealed class Entry
    {
        public int Off;
        public int Len;
        public int Type;
        public int AttrId;
        public string Text;
    }

    private sealed class Parsed
    {
        public int P0, Type, Szl, Sz, TextStart, L, PEnd, AttrId;
    }

    public sealed class Result
    {
        public int Scanned;
        public int SafeRecs;
        public int Keys;
        public int Ok;
        public int Overflow;
        public int Unused;
        public int Dupes;
        public int Patched;
        public int BadFrames;
        public int UsKeys;
        public int UsHit;
        public int UsOverflow;
        public int UsBlocked;
        public bool Equal;
        public long Size;
        public string DstPath = "";
        public List<string> OverflowLines = new List<string>();
        public List<string> UnusedLines = new List<string>();
    }

    // canonical 7bit LEB128；非法编码返回 -1
    private static int Decode7Bit(byte[] b, int pos, int len)
    {
        if (pos < 0 || pos + len > b.Length) return -1;
        int v = 0, shift = 0;
        for (int i = 0; i < len; i++)
        {
            byte c = b[pos + i];
            if (i < len - 1 && (c & 0x80) == 0) return -1;
            if (i == len - 1 && (c & 0x80) != 0) return -1;
            v |= (c & 0x7F) << shift; shift += 7;
        }
        return v;
    }

    // 在 p0（type 字节位置）尝试解析完整记录 [type][size][pre][len][text][post]
    private static Parsed ParseAt(byte[] b, int p0)
    {
        if (p0 < 0 || p0 + 4 >= b.Length) return null;
        int c = b[p0];
        for (int ti = 0; ti < Templates.Length; ti++)
        {
            Template tpl = Templates[ti];
            if (tpl.Type != c) continue;
            for (int szl = 1; szl <= 3; szl++)
            {
                int sz = Decode7Bit(b, p0 + 1, szl);
                if (sz < 0) continue;
                int payloadLen = sz - szl;
                if (payloadLen < tpl.Pre + tpl.Post + 1) continue;
                int textLenPos = p0 + 1 + szl + tpl.Pre;
                for (int lp = 1; lp <= 3; lp++)
                {
                    int L = payloadLen - tpl.Pre - lp - tpl.Post;
                    if (L < 0 || L > 65535) continue;
                    if (Decode7Bit(b, textLenPos, lp) != L) continue;
                    int textStart = textLenPos + lp;
                    if (textStart + L > b.Length) continue;
                    Parsed r = new Parsed();
                    r.P0 = p0; r.Type = tpl.Type; r.Szl = szl; r.Sz = sz;
                    r.TextStart = textStart; r.L = L; r.PEnd = p0 + 1 + sz;
                    r.AttrId = tpl.Pre >= 2 ? BitConverter.ToInt16(b, p0 + 1 + szl) : -1;
                    return r;
                }
            }
        }
        return null;
    }

    private static bool IsTemplateType(byte t)
    {
        for (int i = 0; i < Templates.Length; i++) if (Templates[i].Type == t) return true;
        return false;
    }

    // 全字节扫描：仅在 g.resources 区域内逐字节试解析 + 链校验（记录后必须跟合法记录 type）
    private static List<Entry> ScanText(byte[] bytes, Action<string> log)
    {
        int s0 = 0, s1 = bytes.Length;
        try
        {
            Assembly asm = Assembly.Load(bytes);
            string[] names = asm.GetManifestResourceNames();
            string res = null;
            for (int i = 0; i < names.Length; i++)
                if (names[i].EndsWith(".g.resources", StringComparison.Ordinal)) { res = names[i]; break; }
            if (res != null)
            {
                using (Stream st = asm.GetManifestResourceStream(res))
                {
                    if (st != null)
                    {
                        MemoryStream ms = new MemoryStream();
                        st.CopyTo(ms);
                        byte[] grb = ms.ToArray();
                        Encoding l1 = Encoding.GetEncoding(28591);
                        string head = l1.GetString(grb, 0, Math.Min(48, grb.Length));
                        int gOff = l1.GetString(bytes).IndexOf(head, StringComparison.Ordinal);
                        if (gOff >= 0)
                        {
                            s0 = gOff;
                            s1 = Math.Min(bytes.Length, gOff + grb.Length);
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            log("(资源定位回退到全文件扫描：" + ex.Message + ")");
        }
        log(string.Format("BAML 扫描区域 [{0} .. {1})", s0, s1));

        List<Entry> found = new List<Entry>();
        HashSet<long> seen = new HashSet<long>();
        Encoding latin1 = Encoding.GetEncoding(28591);
        for (int i = s0; i + 4 < s1; i++)
        {
            if (!IsTemplateType(bytes[i])) continue;
            Parsed r = ParseAt(bytes, i);
            if (r == null) continue;
            bool ok = true; int letters = 0;
            for (int q = r.TextStart; q < r.TextStart + r.L; q++)
            {
                byte ch = bytes[q];
                if (ch < 0x20 || ch == 0x7F) { ok = false; break; }
                if ((ch >= 0x41 && ch <= 0x5A) || (ch >= 0x61 && ch <= 0x7A) || ch >= 0x80) letters++;
            }
            if (!ok || letters == 0) continue;
            bool chainOk;
            if (r.PEnd >= bytes.Length - 1) chainOk = true;
            else
            {
                byte nt = bytes[r.PEnd];
                chainOk = nt <= 56;
                if (chainOk && IsTemplateType(nt) && ParseAt(bytes, r.PEnd) == null) chainOk = false;
            }
            if (!chainOk) continue;
            long key = ((long)r.TextStart << 20) | (long)(uint)r.L;
            if (seen.Add(key))
            {
                Entry e = new Entry();
                e.Off = r.TextStart; e.Len = r.L; e.Type = r.Type; e.AttrId = r.AttrId;
                e.Text = latin1.GetString(bytes, r.TextStart, r.L);
                found.Add(e);
            }
        }
        found.Sort(delegate(Entry a, Entry b) { return a.Off.CompareTo(b.Off); });
        return found;
    }

    // 覆写前结构复核：len 前缀 + size 字段 + type 字节必须自洽
    private static bool Validate(byte[] b, Entry e)
    {
        if (e.Off <= 6 || e.Len < 1 || e.Off + e.Len > b.Length) return false;
        for (int lp = 1; lp <= 3; lp++)
        {
            if (Decode7Bit(b, e.Off - lp, lp) != e.Len) continue;
            for (int ti = 0; ti < Templates.Length; ti++)
            {
                Template tpl = Templates[ti];
                for (int szl = 1; szl <= 3; szl++)
                {
                    int sizePos = e.Off - lp - tpl.Pre - szl;
                    if (sizePos < 1) continue;
                    int sz = Decode7Bit(b, sizePos, szl);
                    if (sz < 0) continue;
                    if (sz == tpl.Pre + tpl.Post + lp + e.Len + szl && b[sizePos - 1] == tpl.Type) return true;
                }
            }
        }
        return false;
    }

    // 安全白名单组（经代码字符串碰撞检测与逐组人工审查确定）：
    //   0x24 -110 Text / -14 Content / -65 列头：纯显示文本；
    //   0x24 24 且 off∈[583682,585536]：导航标题（兄弟 Tag 键保持英文，路由不受影响）；
    //   0x24 26/29/45 含空格：一次性 ToolTip 等；无空格的是路由键/元素名，不翻；
    //   0x10 -1 含空格：TextBlock 真文本；无空格是绑定路径。
    private static bool SafeGroup(Entry e)
    {
        if (e.Type == 0x24)
        {
            if (e.AttrId == -110 || e.AttrId == -14 || e.AttrId == -65) return true;
            if (e.AttrId == 24 && e.Off >= 583682 && e.Off <= 585536) return true;
            if ((e.AttrId == 26 || e.AttrId == 29 || e.AttrId == 45) && e.Text.IndexOf(' ') >= 0) return true;
        }
        if (e.Type == 0x10 && e.AttrId == -1 && e.Text.IndexOf(' ') >= 0) return true;
        return false;
    }

    // #US 黑名单：被代码比较/查找/持久化的字符串（路由 key、WMI 索引名、XML LocalName、
    // JSON 契约名、枚举与预设比较值等）。即使误入 us_map 也绝不覆写——安全翻译第一。
    private static readonly HashSet<string> UsBlacklist = new HashSet<string>(StringComparer.Ordinal)
    {
        "About","System","Visuals","Gaming","Network","Services","Peripherals",
        "Startup","Update","Cleanup","AppX","MsiMode","Cpu","Troubleshoot","Stability","Configuration","DriverCleaner","Control",
        "Name","Task","Version","Build","Default","Minimal","SapphireOS","Unrestricted","RemoteSigned","Restricted",
        "Enabled","Disabled","Normal","Forced","Recommended","Classic","Individual","Combined",
        "no","yes","ok","(Hex)","GB RAM"
    };

    // us_map.tsv 与翻译表同目录（存在才启用）；单行条目，文本内换行写作 | 占位，加载时还原
    private static Dictionary<string, string> LoadUsMap(string mapPath, Result R, Action<string> log)
    {
        string p = null;
        try { p = Path.Combine(Path.GetDirectoryName(mapPath), "us_map.tsv"); } catch { }
        if (p == null || !File.Exists(p))
        {
            log("运行时串表：未找到 us_map.tsv，跳过 #US 覆写");
            return null;
        }
        Dictionary<string, string> m = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string raw in File.ReadAllLines(p, Encoding.UTF8))
        {
            string line = raw.TrimEnd();
            if (line.Length == 0 || line[0] == '#') continue;
            int t = line.IndexOf('\t');
            if (t <= 0) continue;
            string k = line.Substring(0, t).Replace("|", "\n");
            string v = line.Substring(t + 1).Replace("|", "\n");
            if (UsBlacklist.Contains(k)) { R.UsBlocked++; continue; }
            if (!m.ContainsKey(k)) m[k] = v;
        }
        R.UsKeys = m.Count;
        log(string.Format("运行时串表：{0} 键（黑名单拦截 {1}）", m.Count, R.UsBlocked));
        return m;
    }

    // .NET 元数据 #US 堆（UTF-16 运行时字符串）等长覆写：
    // 条目 = 压缩长度前缀 + UTF-16LE + 终止 flag byte；新串 char 数 <= 原串时用空格填充到
    // 原 char 数，长度前缀与 flag 字节不动，整条与堆大小零变化（后续堆偏移不受影响）。
    private static void PatchUsHeap(byte[] b, Dictionary<string, string> map, Result R, Action<string> log)
    {
        int usOff, usSize;
        if (!LocateUsHeap(b, log, out usOff, out usSize)) return;
        int end = usOff + usSize;
        int i = usOff + 1; // 首条为空串（单字节 0x00）
        int scanned = 0;
        while (i >= usOff && i < end)
        {
            if (i + 4 > b.Length) break;
            byte c0 = b[i];
            uint len; int plen;
            if ((c0 & 0x80) == 0) { len = c0; plen = 1; }
            else if ((c0 & 0xC0) == 0x80) { len = (uint)(((c0 & 0x3F) << 8) | b[i + 1]); plen = 2; }
            else { len = (uint)(((c0 & 0x1F) << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]); plen = 4; }
            if (len < 1 || i + plen + len > end) break;
            if ((len & 1) == 1 && len >= 3)
            {
                int strStart = i + plen;
                int charBytes = (int)len - 1; // 去掉 flag byte
                string s = Encoding.Unicode.GetString(b, strStart, charBytes);
                string zh;
                if (map.TryGetValue(s, out zh))
                {
                    if (zh.Length <= s.Length)
                    {
                        byte[] zb = Encoding.Unicode.GetBytes(zh);
                        int slots = charBytes / 2;
                        for (int q = 0; q < slots; q++)
                        {
                            if (q * 2 < zb.Length) { b[strStart + q * 2] = zb[q * 2]; b[strStart + q * 2 + 1] = zb[q * 2 + 1]; }
                            else { b[strStart + q * 2] = 0x20; b[strStart + q * 2 + 1] = 0; }
                        }
                        R.UsHit++;
                    }
                    else R.UsOverflow++;
                }
                scanned++;
            }
            i += plen + (int)len;
        }
        log(string.Format("#US 覆写：命中 {0} | 超长 {1}（扫描 {2} 条）", R.UsHit, R.UsOverflow, scanned));
    }

    // PE -> CLI header -> 元数据根(BSJB) -> #US 流定位；任何一步失败即放弃（不影响 BAML 结果）
    private static bool LocateUsHeap(byte[] b, Action<string> log, out int usOff, out int usSize)
    {
        usOff = 0; usSize = 0;
        try
        {
            if (b.Length < 0x200) return false;
            int pe = BitConverter.ToInt32(b, 0x3C);
            if (pe < 0 || pe + 24 > b.Length || b[pe] != 'P' || b[pe + 1] != 'E' || b[pe + 2] != 0 || b[pe + 3] != 0) return false;
            int coff = pe + 4;
            ushort numSec = BitConverter.ToUInt16(b, coff + 2);
            ushort optSize = BitConverter.ToUInt16(b, coff + 16);
            int opt = coff + 20;
            ushort magic = BitConverter.ToUInt16(b, opt);
            if (magic != 0x10B && magic != 0x20B) return false;
            int ddOff = opt + (magic == 0x20B ? 112 : 96);
            uint comRva = BitConverter.ToUInt32(b, ddOff + 14 * 8);
            if (comRva == 0) return false;
            int secTab = opt + optSize;
            int comOff = RvaToOff(b, secTab, numSec, comRva);
            if (comOff < 0 || comOff + 8 > b.Length) return false;
            uint metaRva = BitConverter.ToUInt32(b, comOff + 8);
            int meta = RvaToOff(b, secTab, numSec, metaRva);
            if (meta < 0 || meta + 16 > b.Length) return false;
            if (BitConverter.ToInt32(b, meta) != 0x424A5342) return false; // BSJB
            int verLen = BitConverter.ToInt32(b, meta + 10); // Length 字段在 Signature(4)+Major(2)+Minor(2)+Reserved(2) 之后
            verLen = (verLen + 3) & ~3;
            int p = meta + 14 + verLen; // 版本串从 meta+14 开始（已含填充）
            if (p + 4 > b.Length) return false;
            p += 2; // flags
            ushort nStreams = BitConverter.ToUInt16(b, p); p += 2;
            for (int s = 0; s < nStreams; s++)
            {
                if (p + 8 > b.Length) return false;
                int so = BitConverter.ToInt32(b, p);
                int sz = BitConverter.ToInt32(b, p + 4);
                p += 8;
                int ns = p;
                while (p < b.Length && b[p] != 0) p++;
                string name = Encoding.ASCII.GetString(b, ns, p - ns);
                p = (p + 4) & ~3; // 流名按 4 字节对齐
                if (name == "#US")
                {
                    usOff = meta + so;
                    usSize = sz;
                    bool ok = usOff > 0 && usSize > 4 && usOff + usSize <= b.Length;
                    if (ok) log(string.Format("#US 堆定位：偏移 0x{0:X}，{1:N0} 字节", usOff, usSize));
                    return ok;
                }
            }
            log("#US 定位：流表中无 #US 流");
            return false;
        }
        catch (Exception ex)
        {
            log("#US 定位失败（跳过）：" + ex.Message);
            return false;
        }
    }

    private static int RvaToOff(byte[] b, int secTab, int numSec, uint rva)
    {
        for (int s = 0; s < numSec; s++)
        {
            int se = secTab + s * 40;
            if (se + 40 > b.Length) return -1;
            uint vsz = BitConverter.ToUInt32(b, se + 8);
            uint va = BitConverter.ToUInt32(b, se + 12);
            uint raw = BitConverter.ToUInt32(b, se + 20);
            if (rva >= va && rva < va + Math.Max(vsz, 1)) return (int)(raw + (rva - va));
        }
        return -1;
    }

    private static string Clip(string s, int n)
    {
        if (s.Length <= n) return s;
        return s.Substring(0, n) + "...";
    }

    // write=false 仅校验；write=true 校验并写出 <源名>.zh.exe
    public static Result Run(string srcPath, string mapPath, bool write, Action<string> log)
    {
        Result R = new Result();
        if (log == null) log = delegate(string s) { };
        log("源程序：" + srcPath);
        log("翻译表：" + mapPath);

        byte[] bytes = File.ReadAllBytes(srcPath);
        R.Size = bytes.Length;
        log(string.Format("文件大小：{0:N0} 字节", bytes.Length));

        List<Entry> all = ScanText(bytes, log);
        R.Scanned = all.Count;
        log(string.Format("扫描到文本记录：{0} 条", all.Count));

        List<Entry> safe = new List<Entry>();
        for (int i = 0; i < all.Count; i++) if (SafeGroup(all[i])) safe.Add(all[i]);
        R.SafeRecs = safe.Count;
        Dictionary<string, int> budget = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (Entry e in safe)
        {
            int cur;
            if (!budget.TryGetValue(e.Text, out cur) || e.Len < cur) budget[e.Text] = e.Len;
        }
        log(string.Format("白名单记录：{0} 条（去重 {1} 个键）", safe.Count, budget.Count));

        List<KeyValuePair<string, string>> map = new List<KeyValuePair<string, string>>();
        HashSet<string> seenKey = new HashSet<string>(StringComparer.Ordinal);
        foreach (string raw in File.ReadAllLines(mapPath, Encoding.UTF8))
        {
            string line = raw.TrimEnd();
            if (line.Length == 0 || line[0] == '#') continue;
            int t = line.IndexOf('\t');
            if (t <= 0) continue;
            string k = line.Substring(0, t);
            string v = line.Substring(t + 1);
            if (!seenKey.Add(k)) { R.Dupes++; continue; }
            map.Add(new KeyValuePair<string, string>(k, v));
        }
        R.Keys = map.Count;

        Dictionary<string, string> zhSet = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (KeyValuePair<string, string> kv in map)
        {
            int b;
            if (!budget.TryGetValue(kv.Key, out b))
            {
                R.Unused++;
                if (R.UnusedLines.Count < 30) R.UnusedLines.Add(Clip(kv.Key, 60));
                continue;
            }
            int need = Encoding.UTF8.GetByteCount(kv.Value);
            if (need > b)
            {
                R.Overflow++;
                if (R.OverflowLines.Count < 30)
                    R.OverflowLines.Add(string.Format("超 {0}B（预算 {1}）：{2}  ← {3}", need - b, b, kv.Value, Clip(kv.Key, 48)));
            }
            else
            {
                R.Ok++;
                zhSet[kv.Key] = kv.Value;
            }
        }
        log(string.Format("翻译表：{0} 键（重复 {1}）| 预算通过 {2} | 超限 {3} | 未匹配 {4}",
            R.Keys, R.Dupes, R.Ok, R.Overflow, R.Unused));
        foreach (string s in R.OverflowLines) log("  [超限] " + s);
        foreach (string s in R.UnusedLines) log("  [未匹配] " + s);

        if (!write)
        {
            log("（仅校验模式，未写出文件）");
            return R;
        }

        // 覆写：仅对预算通过的键；长度前缀与记录框架保持字节级不动
        HashSet<string> patchedKeys = new HashSet<string>(StringComparer.Ordinal);
        foreach (Entry e in safe)
        {
            string zh;
            if (!zhSet.TryGetValue(e.Text, out zh)) continue;
            if (!Validate(bytes, e)) { R.BadFrames++; continue; }
            byte[] zb = Encoding.UTF8.GetBytes(zh);
            for (int i = 0; i < e.Len; i++) bytes[e.Off + i] = i < zb.Length ? zb[i] : (byte)0x20;
            R.Patched++;
            patchedKeys.Add(e.Text);
        }

        // 运行时字符串堆(#US)：仅 us_map 白名单 + 内置黑名单兜底，等长 UTF-16 填充
        Dictionary<string, string> usMap = LoadUsMap(mapPath, R, log);
        if (usMap != null && usMap.Count > 0) PatchUsHeap(bytes, usMap, R, log);

        string dir = Path.GetDirectoryName(srcPath);
        string name = Path.GetFileNameWithoutExtension(srcPath);
        R.DstPath = Path.Combine(dir, name + ".zh.exe");
        File.WriteAllBytes(R.DstPath, bytes);
        R.Equal = bytes.Length == R.Size;

        log(string.Format("覆写记录：{0} 条（{1} 个键）| 坏帧：{2}", R.Patched, patchedKeys.Count, R.BadFrames));
        if (patchedKeys.Count != zhSet.Count)
            log(string.Format("提示：有 {0} 个键未命中白名单记录", zhSet.Count - patchedKeys.Count));
        log("已写出：" + R.DstPath);
        log("文件等长校验：" + (R.Equal ? "通过" : "失败！"));
        return R;
    }
}

internal sealed class MainForm : Form
{
    private readonly TextBox txtSrc = new TextBox();
    private readonly TextBox txtMap = new TextBox();
    private readonly TextBox txtLog = new TextBox();
    private readonly Button btnBrowseSrc = new Button();
    private readonly Button btnBrowseMap = new Button();
    private readonly Button btnBuild = new Button();
    private readonly Button btnCheck = new Button();
    private readonly Label lblStatus = new Label();
    private readonly Panel header = new Panel();
    private int hoverBtn = -1; // 0=最小化 1=关闭 -1=无

    public MainForm()
    {
        Text = "XOS Toolkit 汉化工具";
        FormBorderStyle = FormBorderStyle.None; // 无边框单窗口：仅保留自绘标题栏
        ClientSize = new Size(660, 500);
        StartPosition = FormStartPosition.CenterScreen;
        DoubleBuffered = true;
        Font = new Font("Microsoft YaHei UI", 9F, FontStyle.Regular, GraphicsUnit.Point);
        BackColor = Color.FromArgb(245, 247, 250);

        header.Dock = DockStyle.Top;
        header.Height = 48;
        header.Paint += HeaderPaint;
        header.MouseDown += HeaderMouseDown;
        header.MouseMove += HeaderMouseMove;
        header.MouseLeave += HeaderMouseLeave;
        header.Cursor = Cursors.SizeAll;
        Controls.Add(header);

        Label lblSrc = new Label();
        lblSrc.Text = "源程序";
        lblSrc.AutoSize = true;
        lblSrc.Location = new Point(14, 64);
        lblSrc.ForeColor = Color.FromArgb(70, 78, 90);
        Controls.Add(lblSrc);

        txtSrc.Location = new Point(14, 84);
        txtSrc.Size = new Size(536, 25);
        txtSrc.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
        txtSrc.Text = Core.DefaultSrc;
        Controls.Add(txtSrc);

        StyleButton(btnBrowseSrc, false);
        btnBrowseSrc.Text = "浏览";
        btnBrowseSrc.Location = new Point(558, 83);
        btnBrowseSrc.Size = new Size(88, 27);
        btnBrowseSrc.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        btnBrowseSrc.Click += BrowseSrc;
        Controls.Add(btnBrowseSrc);

        Label lblMap = new Label();
        lblMap.Text = "翻译表";
        lblMap.AutoSize = true;
        lblMap.Location = new Point(14, 122);
        lblMap.ForeColor = Color.FromArgb(70, 78, 90);
        Controls.Add(lblMap);

        txtMap.Location = new Point(14, 142);
        txtMap.Size = new Size(536, 25);
        txtMap.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
        txtMap.Text = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "zh_map.tsv");
        Controls.Add(txtMap);

        StyleButton(btnBrowseMap, false);
        btnBrowseMap.Text = "浏览";
        btnBrowseMap.Location = new Point(558, 141);
        btnBrowseMap.Size = new Size(88, 27);
        btnBrowseMap.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        btnBrowseMap.Click += BrowseMap;
        Controls.Add(btnBrowseMap);

        StyleButton(btnBuild, true);
        btnBuild.Text = "生成汉化版 exe";
        btnBuild.Location = new Point(14, 186);
        btnBuild.Size = new Size(160, 36);
        btnBuild.Click += delegate(object s, EventArgs e) { RunCore(true); };
        Controls.Add(btnBuild);

        StyleButton(btnCheck, false);
        btnCheck.Text = "仅校验";
        btnCheck.Location = new Point(186, 186);
        btnCheck.Size = new Size(110, 36);
        btnCheck.Click += delegate(object s, EventArgs e) { RunCore(false); };
        Controls.Add(btnCheck);

        txtLog.Location = new Point(14, 238);
        txtLog.Size = new Size(632, 212);
        txtLog.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        txtLog.Multiline = true;
        txtLog.ReadOnly = true;
        txtLog.ScrollBars = ScrollBars.Vertical;
        txtLog.BackColor = Color.White;
        txtLog.Font = new Font("Consolas", 9F, FontStyle.Regular, GraphicsUnit.Point);
        Controls.Add(txtLog);

        lblStatus.Text = "就绪";
        lblStatus.AutoSize = true;
        lblStatus.Location = new Point(14, 468);
        lblStatus.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
        lblStatus.ForeColor = Color.FromArgb(100, 108, 120);
        Controls.Add(lblStatus);
    }

    private void HeaderPaint(object sender, PaintEventArgs e)
    {
        Panel p = (Panel)sender;
        using (LinearGradientBrush br = new LinearGradientBrush(
            new Rectangle(0, 0, p.Width, p.Height),
            Color.FromArgb(90, 202, 255), Color.FromArgb(10, 132, 255), LinearGradientMode.Horizontal))
        {
            e.Graphics.FillRectangle(br, 0, 0, p.Width, p.Height);
        }
        using (Font f = new Font("Microsoft YaHei UI", 13F, FontStyle.Bold))
        using (SolidBrush w = new SolidBrush(Color.White))
        {
            e.Graphics.DrawString("XOS Toolkit 汉化工具", f, w, 14, 11);
        }
        using (Font f2 = new Font("Microsoft YaHei UI", 8.5F))
        using (SolidBrush w2 = new SolidBrush(Color.FromArgb(215, 255, 255, 255)))
        {
            string tip = "安全等长覆写 · 白名单文本";
            SizeF sz = e.Graphics.MeasureString(tip, f2);
            e.Graphics.DrawString(tip, f2, w2, p.Width - sz.Width - 106, 17);
        }

        // 自绘标题栏按钮：最小化 / 关闭（维持单窗口观感，不引入系统标题栏）
        Rectangle rcMin = MinRect();
        Rectangle rcClose = CloseRect();
        if (hoverBtn == 1)
        {
            using (SolidBrush b = new SolidBrush(Color.FromArgb(232, 17, 35)))
                e.Graphics.FillRectangle(b, rcClose);
        }
        else if (hoverBtn == 0)
        {
            using (SolidBrush b = new SolidBrush(Color.FromArgb(70, 255, 255, 255)))
                e.Graphics.FillRectangle(b, rcMin);
        }
        e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
        using (Pen pen = new Pen(Color.White, 1.6F))
        {
            int cx = rcClose.Left + rcClose.Width / 2;
            int cy = rcClose.Top + rcClose.Height / 2;
            e.Graphics.DrawLine(pen, cx - 5, cy - 5, cx + 5, cy + 5);
            e.Graphics.DrawLine(pen, cx - 5, cy + 5, cx + 5, cy - 5);
            int mx = rcMin.Left + rcMin.Width / 2;
            int my = rcMin.Top + rcMin.Height / 2;
            e.Graphics.DrawLine(pen, mx - 6, my, mx + 6, my);
        }
    }

    private Rectangle MinRect()
    {
        return new Rectangle(header.Width - 92, 0, 46, header.Height);
    }

    private Rectangle CloseRect()
    {
        return new Rectangle(header.Width - 46, 0, 46, header.Height);
    }

    private void HeaderMouseDown(object sender, MouseEventArgs e)
    {
        if (e.Button != MouseButtons.Left) return;
        if (CloseRect().Contains(e.Location)) { Close(); return; }
        if (MinRect().Contains(e.Location)) { WindowState = FormWindowState.Minimized; return; }
        ReleaseCapture();
        SendMessage(Handle, 0xA1, (IntPtr)0x2, IntPtr.Zero); // WM_NCLBUTTONDOWN / HTCAPTION：拖动窗口
    }

    private void HeaderMouseMove(object sender, MouseEventArgs e)
    {
        int h = -1;
        if (CloseRect().Contains(e.Location)) h = 1;
        else if (MinRect().Contains(e.Location)) h = 0;
        if (h != hoverBtn)
        {
            hoverBtn = h;
            header.Invalidate();
            header.Cursor = h >= 0 ? Cursors.Hand : Cursors.SizeAll;
        }
    }

    private void HeaderMouseLeave(object sender, EventArgs e)
    {
        if (hoverBtn != -1)
        {
            hoverBtn = -1;
            header.Invalidate();
        }
    }

    protected override CreateParams CreateParams
    {
        get
        {
            CreateParams cp = base.CreateParams;
            cp.ClassStyle |= 0x20000; // CS_DROPSHADOW：无边框窗口投影
            return cp;
        }
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        ApplyCorners();
    }

    // Win11 走 DWM 圆角；Win10 用 8px Region 裁切（与本机其他工具一致）
    private void ApplyCorners()
    {
        try
        {
            if (Environment.OSVersion.Version.Build >= 22000)
            {
                int pref = 2; // DWMWCP_ROUND
                if (DwmSetWindowAttribute(Handle, 33, ref pref, 4) == 0) return;
            }
        }
        catch { }
        try
        {
            using (GraphicsPath gp = RoundedRect(new Rectangle(0, 0, Width, Height), 8))
                Region = new Region(gp);
        }
        catch { }
    }

    private static GraphicsPath RoundedRect(Rectangle r, int radius)
    {
        int d = radius * 2;
        GraphicsPath gp = new GraphicsPath();
        gp.AddArc(r.X, r.Y, d, d, 180, 90);
        gp.AddArc(r.Right - d, r.Y, d, d, 270, 90);
        gp.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
        gp.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
        gp.CloseFigure();
        return gp;
    }

    [DllImport("user32.dll")]
    private static extern bool ReleaseCapture();

    [DllImport("user32.dll")]
    private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

    private static void StyleButton(Button b, bool primary)
    {
        b.FlatStyle = FlatStyle.Flat;
        b.FlatAppearance.BorderSize = 1;
        b.FlatAppearance.BorderColor = Color.FromArgb(10, 132, 255);
        b.BackColor = primary ? Color.FromArgb(10, 132, 255) : Color.White;
        b.ForeColor = primary ? Color.White : Color.FromArgb(10, 132, 255);
        b.Cursor = Cursors.Hand;
        b.UseVisualStyleBackColor = false;
    }

    private void BrowseSrc(object sender, EventArgs e)
    {
        using (OpenFileDialog d = new OpenFileDialog())
        {
            d.Filter = "可执行文件 (*.exe)|*.exe|所有文件 (*.*)|*.*";
            if (File.Exists(txtSrc.Text)) d.FileName = txtSrc.Text;
            if (d.ShowDialog(this) == DialogResult.OK) txtSrc.Text = d.FileName;
        }
    }

    private void BrowseMap(object sender, EventArgs e)
    {
        using (OpenFileDialog d = new OpenFileDialog())
        {
            d.Filter = "翻译表 (*.tsv)|*.tsv|文本文件 (*.txt)|*.txt|所有文件 (*.*)|*.*";
            if (File.Exists(txtMap.Text)) d.FileName = txtMap.Text;
            if (d.ShowDialog(this) == DialogResult.OK) txtMap.Text = d.FileName;
        }
    }

    private void AppendLog(string s)
    {
        txtLog.AppendText(s + Environment.NewLine);
        txtLog.SelectionStart = txtLog.TextLength;
        txtLog.ScrollToCaret();
        Application.DoEvents();
    }

    private void SetBusy(bool busy)
    {
        btnBuild.Enabled = !busy;
        btnCheck.Enabled = !busy;
        btnBrowseSrc.Enabled = !busy;
        btnBrowseMap.Enabled = !busy;
        Cursor = busy ? Cursors.WaitCursor : Cursors.Default;
    }

    private void RunCore(bool write)
    {
        string src = txtSrc.Text.Trim();
        string map = txtMap.Text.Trim();
        if (src.Length == 0 || !File.Exists(src))
        {
            MessageBox.Show(this, "源程序不存在：\r\n" + src, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        if (map.Length == 0 || !File.Exists(map))
        {
            MessageBox.Show(this, "翻译表不存在：\r\n" + map, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        txtLog.Clear();
        SetBusy(true);
        lblStatus.Text = write ? "正在生成汉化版..." : "正在校验...";
        try
        {
            Core.Result r = Core.Run(src, map, write, AppendLog);
            string done;
            if (write)
            {
                done = string.Format("完成：覆写 {0} 条记录（{1} 键）+ 运行时串 {2} -> {3}", r.Patched, r.Keys - r.Overflow - r.Unused, r.UsHit, r.DstPath);
                AppendLog("完成。" + (r.Equal ? "" : " 注意：文件等长校验失败！"));
            }
            else
            {
                done = string.Format("校验完成：通过 {0} / 超限 {1} / 未匹配 {2}", r.Ok, r.Overflow, r.Unused);
            }
            lblStatus.Text = done;
        }
        catch (Exception ex)
        {
            lblStatus.Text = "失败：" + ex.Message;
            AppendLog("错误：" + ex.Message);
            MessageBox.Show(this, ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            SetBusy(false);
        }
    }
}

internal static class Program
{
    [STAThread]
    internal static void Main(string[] args)
    {
        if (args.Length > 0 && string.Equals(args[0], "--auto", StringComparison.OrdinalIgnoreCase))
        {
            AutoRun();
            return;
        }
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new MainForm());
    }

    // 无窗口自检/批处理模式：默认路径执行并写 XosZhTool.log
    private static void AutoRun()
    {
        string dir = AppDomain.CurrentDomain.BaseDirectory;
        string map = Path.Combine(dir, "zh_map.tsv");
        List<string> lines = new List<string>();
        int code = 0;
        try
        {
            Core.Result r = Core.Run(Core.DefaultSrc, map, true, delegate(string s) { lines.Add(s); });
            lines.Add(string.Format("AUTO 结果：扫描 {0} | 白名单 {1} | 键 {2} | 覆写 {3} | 超限 {4} | 未匹配 {5} | 坏帧 {6} | 等长 {7} | US命中 {8}",
                r.Scanned, r.SafeRecs, r.Keys, r.Patched, r.Overflow, r.Unused, r.BadFrames, r.Equal ? "是" : "否", r.UsHit));
            if (r.BadFrames != 0 || !r.Equal) code = 2;
        }
        catch (Exception ex)
        {
            lines.Add("错误：" + ex.Message);
            code = 1;
        }
        try
        {
            File.WriteAllText(Path.Combine(dir, "XosZhTool.log"),
                string.Join(Environment.NewLine, lines.ToArray()) + Environment.NewLine, new UTF8Encoding(false));
        }
        catch { }
        Environment.ExitCode = code;
    }
}
