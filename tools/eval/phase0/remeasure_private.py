"""サブドメインとprivateサフィックス上のラベルの、ランダム文字列の該当率を測る。

元は別のセッションのレビューで作成したスクリプト(m2.py)。参照実装がPunycodeを
除外するようになったため、見出しを整理し、ホスト単位の集計を加えた。

集計の単位:
  - 先頭のラベル:サブドメインの先頭のラベルだけで判定(docs/research/phase0.md の初回の集計と同じ)
  - ホスト単位:サブドメインのラベルのいずれかが該当すれば該当(6.3の定義。実装と同じ)
  - privateサフィックス上:サフィックスより左のラベルのいずれかが該当すれば該当
"""
import csv, gzip, sys, re, collections
from urllib.parse import urlsplit
base = sys.argv[1]
sys.path.insert(0, base)
from randomcheck import label_hits
exec(open(base + "/psl_lib.py").read())
load_psl(base + "/phish/psl.dat")


def phish():
    for m in ["202607", "202608", "202609"]:
        for r in csv.DictReader(open(f"{base}/phish/repo/2026/{m}.csv", encoding="utf-8", errors="replace")):
            h = (urlsplit(r["URL"] if "://" in r["URL"] else "http://" + r["URL"]).hostname or "").lower()
            if h and not re.fullmatch(r"[0-9.]+", h):
                yield h


def crux(ranks):
    with gzip.open(f"{base}/crux/data/country/jp/202609.csv.gz", "rt") as f:
        for r in csv.DictReader(f):
            if int(r["rank"]) in ranks:
                h = urlsplit(r["origin"]).hostname
                if h:
                    yield h.lower()


for title, hosts in [("フィッシング", phish()), ("正常(50万〜100万位)", crux({1000000})), ("正常(上位1万)", crux({1000, 5000, 10000}))]:
    sub_hosts, priv_hosts = {}, {}
    for h in hosts:
        try:
            ps_i, ps_any = icann_suffix(h), any_suffix(h)
        except Exception:
            continue
        if ps_any != ps_i:
            left = h[: -len(ps_any) - 1] if h != ps_any else ""
            if left:
                priv_hosts.setdefault(h, ([l for l in left.split(".") if l and l != "www"], ps_any))
            continue
        reg = registrable(h, ps_i)
        labels = [s for s in h[: -len(reg)].rstrip(".").split(".") if s and s != "www"]
        if labels:
            sub_hosts.setdefault(h, labels)
    n = len(sub_hosts)
    first = sum(label_hits(ls[0]) for ls in sub_hosts.values()) / max(n, 1)
    anyl = sum(any(label_hits(l) for l in ls) for ls in sub_hosts.values()) / max(n, 1)
    multi = sum(len(ls) > 1 for ls in sub_hosts.values())
    print(f"{title}")
    print(f"  サブドメインのあるホスト {n}(うちラベルが2つ以上 {multi})")
    print(f"    先頭のラベルで判定: {first:.1%}  /  いずれかのラベルで判定(ホスト単位): {anyl:.1%}")
    pn = len(priv_hosts)
    if pn:
        phit = sum(any(label_hits(l) for l in ls) for ls, _ in priv_hosts.values()) / pn
        print(f"  privateサフィックス上のホスト {pn}:いずれかのラベルで判定 {phit:.1%}")
        top = collections.Counter(s for _, s in priv_hosts.values()).most_common(5)
        print("    多いサフィックス:", ", ".join(f"{s}({c})" for s, c in top))
