#!/usr/bin/env node
// 规则关系判断的回归测试。
//
// 为什么单独测：这套逻辑是纯函数，但结论全是"提醒人要不要删"，
// 误报一次就让人不敢动配置，漏报一次就删出半套。用点界面抽查根本覆盖不到边界。
//
// 直接从 src/webui/index.html 里抽出那段代码来跑——测试的就是线上跑的那份，
// 不复制粘贴一份到测试里（复制的那份迟早和真身分叉）。

const fs = require("fs");
const path = require("path");

const HTML = path.join(__dirname, "..", "src", "webui", "index.html");
const src = fs.readFileSync(HTML, "utf8");

const START = "// ---------- 规则关系网络 ----------";
const END = "  function renderRules(){";
const a = src.indexOf(START);
const b = src.indexOf(END, a);
if (a < 0 || b < 0) {
  console.error("找不到关系逻辑代码块，index.html 结构变了？");
  process.exit(1);
}
const block = src.slice(a, b);

// relPanelHtml 里用到 t()/esc()，定义时不执行，给个桩即可
const sandbox = new Function(
  "state",
  "rulesDraft",
  "t",
  "esc",
  block + "\nreturn {ruleScope, scopeOverlap, sameConditions, ruleRelations, pathUnder, hostMatches, hostsRelated};"
);

function mount(rules, cfg) {
  const state = { cfg: cfg || {} };
  return sandbox(state, () => rules, (k, p) => k, (s) => String(s));
}

const rule = (name, matches) => ({ name, matches: matches || [] });
const host = (v) => ({ kind: "host", value: v });
const pth = (v) => ({ kind: "path", value: v });

let failed = 0;
function ok(cond, label, extra) {
  if (cond) {
    console.log("  ✓ " + label);
  } else {
    failed++;
    console.log("  ✗ " + label + (extra ? "  → " + extra : ""));
  }
}

console.log("路径归属");
{
  const { pathUnder } = mount([]);
  ok(pathUnder("/api/v1", "/api") === true, "/api/v1 在 /api 下");
  ok(pathUnder("/api", "/api") === true, "/api 等于 /api");
  // 这条是最容易写错的：裸字符串前缀会把 /apixyz 判成 /api 的子路径
  ok(pathUnder("/apixyz", "/api") === false, "/apixyz 不在 /api 下（不能裸前缀比较）");
  ok(pathUnder("/api", "/") === true, "/api 在 / 下");
  ok(pathUnder("/api/", "/api") === true, "尾部斜杠不影响判断");
  ok(pathUnder("/", "/api") === false, "/ 不在 /api 下");
}

console.log("域名匹配");
{
  const { hostMatches } = mount([]);
  ok(hostMatches("a.example.com", "a.example.com") === true, "精确命中");
  ok(hostMatches("A.Example.com", "a.example.com") === true, "大小写不敏感");
  ok(hostMatches("*.example.com", "a.example.com") === true, "通配 *.example.com 命中子域");
  ok(hostMatches("*.example.com", "example.com") === false, "通配不命中裸域");
  ok(hostMatches("*", "anything.dev") === true, "* 命中一切");
  ok(hostMatches("a.example.com", "b.example.com") === false, "不同域名不命中");
  ok(hostMatches("", "a.example.com") === false, "空条件不算命中");
}

console.log("规则重叠");
{
  const rules = [
    rule("全站", []),
    rule("接口", [host("a.example.com"), pth("/api")]),
    rule("接口 v1", [host("a.example.com"), pth("/api/v1")]),
    rule("相似前缀", [host("a.example.com"), pth("/apixyz")]),
    rule("别的域", [host("b.example.com"), pth("/api")]),
  ];
  const app = mount(rules);
  ok(app.ruleRelations(0).rules.length === 4, "无条件规则和所有规则都重叠", app.ruleRelations(0).rules.length);
  const v1rel = app.ruleRelations(2).rules.map((r) => r.name);
  ok(v1rel.indexOf("接口") >= 0, "/api/v1 与 /api 重叠", v1rel.join(","));
  const prefixRel = app.ruleRelations(3).rules.map((r) => r.name);
  ok(prefixRel.indexOf("接口") < 0, "/apixyz 与 /api 不重叠（原来的误报）", prefixRel.join(","));
  ok(prefixRel.indexOf("接口 v1") < 0, "/apixyz 与 /api/v1 不重叠", prefixRel.join(","));
  const otherHost = app.ruleRelations(4).rules.map((r) => r.name);
  ok(otherHost.indexOf("接口") < 0, "不同域名不重叠", otherHost.join(","));
}

console.log("完全重复的规则");
{
  const rules = [
    rule("先写的", [host("a.example.com")]),
    rule("后写的", [host("a.example.com")]),
  ];
  const app = mount(rules);
  const rel = app.ruleRelations(0);
  ok(rel.same.length === 1 && rel.same[0] === "后写的", "认出条件完全相同的规则", JSON.stringify(rel.same));
  // 顺序也重要：后写的永远生效，前一条等于摆设
  ok(rel.rules[0].order === 1, "标出重叠规则的位置，才知道谁盖谁");
}

console.log("空条件不该被当成重复");
{
  const rules = [rule("全域 A", []), rule("全域 B", [])];
  const app = mount(rules);
  ok(app.ruleRelations(0).same.length === 0, "两条无条件规则只是重叠，不算完全重复");
}

console.log("受影响的转发目标");
{
  const cfg = {
    routes: [
      { name: "r-api", host: "a.example.com", path_prefix: "/api" },
      { name: "r-apixyz", host: "a.example.com", path_prefix: "/apixyz" },
      { name: "r-other", host: "b.example.com", path_prefix: "/api" },
    ],
    sites: [{ name: "主站", hosts: ["a.example.com"] }],
    apps: [{ name: "demo", hosts: ["*.example.com"] }],
  };
  const rules = [rule("接口", [host("a.example.com"), pth("/api")])];
  const app = mount(rules, cfg);
  const t = app.ruleRelations(0).targets.map((x) => x.kind + ":" + x.name);
  ok(t.indexOf("route:r-api") >= 0, "命中 /api 路由", t.join(","));
  ok(t.indexOf("route:r-apixyz") < 0, "不命中 /apixyz 路由", t.join(","));
  ok(t.indexOf("route:r-other") < 0, "不命中别的域名", t.join(","));
  ok(t.indexOf("site:主站") >= 0, "命中同域名站点", t.join(","));
  // 规则写精确域名、应用写通配域名，也应该算相关
  ok(t.indexOf("app:demo") >= 0, "规则精确域名命中应用的通配域名", t.join(","));
}

console.log("");
if (failed) {
  console.log("失败 " + failed + " 项");
  process.exit(1);
}
console.log("关系判断全部通过");
