import csv, gzip, sys, re, collections
from urllib.parse import urlsplit
base = sys.argv[1]
exec(open(base + "/psl_lib.py").read())
load_psl(base + "/phish/psl.dat")

def split(host):
    ps_i, ps_any = icann_suffix(host), any_suffix(host)
    reg = registrable(host, ps_i)
    priv = ps_any != ps_i
    reg_label = reg[: -len(ps_i) - 1]
    sub = host[: -len(reg)].rstrip(".")
    return reg, reg_label, sub, ps_i.rsplit(".", 1)[-1], priv

V = set("aeiou")
def feats(label):
    l = label.lower()
    letters = re.sub(r"[^a-z]", "", l)
    if not letters: return {}
    vr = sum(c in V for c in letters) / len(letters)
    run = max((len(m) for m in re.findall(r"[^aeiou\d-]+", l)), default=0)
    digit = bool(re.search(r"\d", l))
    mixed = digit and bool(re.search(r"[a-z]", l))
    return {"len": len(l), "vr": vr, "run": run, "digit": digit, "mixed": mixed}

RULES = {
    "A:簡易(計画時の判定)": lambda f: f and f["len"] >= 4 and (f["vr"] < 0.25 or f["run"] >= 5 or f["digit"]),
    "B:5文字以上・母音<20%か子音5連続": lambda f: f and f["len"] >= 5 and (f["vr"] < 0.2 or f["run"] >= 5),
    "C:Bに加え、6文字以上で英数字混在": lambda f: f and ((f["len"] >= 5 and (f["vr"] < 0.2 or f["run"] >= 5)) or (f["len"] >= 6 and f["mixed"])),
}
ABUSED = ["top", "help", "cfd", "icu", "shop", "cn", "info", "me", "co", "xyz", "asia", "study", "cc", "sbs", "lol", "vip"]

def load_phish():
    hosts = []
    for m in ["202607", "202608", "202609"]:
        for r in csv.DictReader(open(f"{base}/phish/repo/2026/{m}.csv", encoding="utf-8", errors="replace")):
            h = (urlsplit(r["URL"] if "://" in r["URL"] else "http://" + r["URL"]).hostname or "").lower()
            if h and not re.fullmatch(r"[0-9.]+", h): hosts.append(h)
    return hosts

def load_crux(path, ranks):
    hosts = []
    with gzip.open(path, "rt") as f:
        for r in csv.DictReader(f):
            if int(r["rank"]) in ranks:
                h = urlsplit(r["origin"]).hostname
                if h: hosts.append(h.lower())
    return hosts

def measure(name, hosts):
    regs = {}; subs = []
    for h in hosts:
        try: reg, rl, sub, tld, priv = split(h)
        except Exception: continue
        if priv: continue
        regs.setdefault(reg, (rl, tld))
        if sub and sub != "www": subs.append(sub.split(".")[0])
    n = len(regs)
    out = {"name": name, "n": n, "nsub": len(subs)}
    for k, fn in RULES.items():
        out["reg " + k] = sum(bool(fn(feats(rl))) for rl, _ in regs.values()) / n
        out["sub " + k] = sum(bool(fn(feats(s))) for s in subs) / max(len(subs), 1)
    tl = collections.Counter(t for _, t in regs.values())
    out["tld"] = {t: tl[t] / n for t in ABUSED}
    out["tld_com"] = tl["com"] / n
    return out

jp = base + "/crux/data/country/jp/202609.csv.gz"
sets = [
    measure("フィッシング(JPCERT 7〜9月)", load_phish()),
    measure("正常:日本 上位1万", load_crux(jp, {1000, 5000, 10000})),
    measure("正常:日本 50万〜100万位", load_crux(jp, {1000000})),
]
print("登録ドメイン数:", {s["name"]: s["n"] for s in sets})
print("\n[ランダム文字列の該当率:登録ドメインのラベル]")
for k in RULES:
    print(f"  {k}: " + " / ".join(f"{s['name']} {s['reg ' + k]:.1%}" for s in sets))
print("\n[ランダム文字列の該当率:サブドメインの先頭ラベル(www除く)]")
for k in RULES:
    print(f"  {k}: " + " / ".join(f"{s['name']} {s['sub ' + k]:.1%}" for s in sets))
print("\n[TLDの割合(登録ドメイン単位)]")
print(f"  .com: " + " / ".join(f"{s['tld_com']:.1%}" for s in sets))
for t in ABUSED:
    vals = [s["tld"][t] for s in sets]
    ratio = vals[0] / vals[2] if vals[2] else float("inf")
    print(f"  .{t}: " + " / ".join(f"{v:.2%}" for v in vals) + f"   (フィッシング÷50万〜100万位 = {ratio:.0f}倍)")

print("\n[正規の略語・普通の単語の判定(A/B/C)]")
for w in ["smbc", "kddi", "mufg", "jcb", "nhk", "ntt", "rakuten", "drawboardhq", "yqspzy", "jgfjfjfg", "cj49xv9v", "kvqlv", "ywhrz", "cpygl", "0c3rd589", "9mn9u7", "heyunlongshun", "mail2", "web3", "x-trend"]:
    print(f"  {w}: " + " ".join("○" if fn(feats(w)) else "-" for fn in RULES.values()))
