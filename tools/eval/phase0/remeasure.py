import csv, gzip, sys, re
from urllib.parse import urlsplit
base = sys.argv[1]
sys.path.insert(0, base)
from randomcheck import label_hits, label_hits_unsplit
exec(open(base + "/psl_lib.py").read())
load_psl(base + "/phish/psl.dat")

def parts(h):
    ps_i, ps_any = icann_suffix(h), any_suffix(h)
    if ps_any != ps_i: return None
    reg = registrable(h, ps_i)
    return reg[: -len(ps_i) - 1], [s for s in h[: -len(reg)].rstrip(".").split(".") if s and s != "www"][:1]

def phish():
    for m in ["202607", "202608", "202609"]:
        for r in csv.DictReader(open(f"{base}/phish/repo/2026/{m}.csv", encoding="utf-8", errors="replace")):
            h = (urlsplit(r["URL"] if "://" in r["URL"] else "http://" + r["URL"]).hostname or "").lower()
            if h and not re.fullmatch(r"[0-9.]+", h): yield h

def crux(ranks):
    with gzip.open(f"{base}/crux/data/country/jp/202609.csv.gz", "rt") as f:
        for r in csv.DictReader(f):
            if int(r["rank"]) in ranks:
                h = urlsplit(r["origin"]).hostname
                if h: yield h.lower()

def measure(hosts):
    regs, subs = {}, []
    for h in hosts:
        try: p = parts(h)
        except Exception: continue
        if not p: continue
        regs.setdefault(p[0], 1); subs += p[1]
    out = {}
    for name, fn in [("区切らない(初回)", label_hits_unsplit), ("ハイフンで区切る(採用)", label_hits)]:
        out[name] = (sum(fn(l) for l in regs) / len(regs), sum(fn(s) for s in subs) / max(len(subs), 1))
    return len(regs), out, regs

for title, hosts in [("フィッシング", phish()), ("正常(50万〜100万位)", crux({1000000})), ("正常(上位1万)", crux({1000, 5000, 10000}))]:
    n, out, regs = measure(hosts)
    print(f"{title}: 登録ドメイン {n}")
    for k, (r, s) in out.items():
        print(f"  {k}: 登録ドメイン {r:.1%} / サブドメイン先頭 {s:.1%}")
    if title.startswith("正常(50万"):
        hits = [l for l in regs if label_hits(l)]
        import random; random.seed(3)
        print("  該当例(無作為20件):", ", ".join(random.sample(hits, 20)))

print("\n[例の判定]")
for w in ["xfqear8f", "cj49xv9v", "yqspzy", "jgfjfjfg", "0c3rd589", "9mn9u7", "tmsvr", "kvqlv", "ockvv", "hsije",
          "smbc", "kddi", "mufg", "x-trend", "drawboardhq", "script", "crypto", "twitch", "strength", "french", "rhythm"]:
    print(f"  {w}: {'該当' if label_hits(w) else '-'}")
