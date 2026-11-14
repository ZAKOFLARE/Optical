#!/usr/bin/env python3
"""检查 WebUI 里 `$("id")` 引用的元素是否真的存在。

这条检查是被真实事故逼出来的：给「可信代理」加了回填与保存代码，却漏了那行
HTML 字段，于是每次进入配置/后端页面都抛
`Cannot set properties of null (setting 'value')` ——
浏览器控制台只有一行红字，用户看到的却是"点进去就卡住"。

跑法：python3 scripts/check_webui.py
退出码非 0 表示有悬空引用。
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "webui" / "index.html"

# 运行时才创建的元素（规则卡片的展开面板、日志面板等），静态文件里搜不到属正常
DYNAMIC = re.compile(r"^(rel-\d+|log-\d+|hist-|app-log-)")


def main() -> int:
    text = SRC.read_text(encoding="utf-8")
    ids = set(re.findall(r'\bid="([^"]+)"', text))

    refs: dict[str, int] = {}
    for m in re.finditer(r'\$\("([^"]+)"\)', text):
        # 行号：数一下前面有多少换行
        refs.setdefault(m.group(1), text.count("\n", 0, m.start()) + 1)

    missing = {
        k: ln for k, ln in refs.items() if k not in ids and not DYNAMIC.match(k)
    }
    if missing:
        for k, ln in sorted(missing.items(), key=lambda x: x[1]):
            print(f"  悬空引用 id=\"{k}\"  行 {ln}")
        print(f"FAIL: {len(missing)} 个 id 在 HTML 里不存在")
        return 1

    print(f"OK: {len(refs)} 个引用全部有对应元素（{len(ids)} 个 id）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
