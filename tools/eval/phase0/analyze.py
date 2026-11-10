import csv, sys, re, math, collections
from urllib.parse import urlsplit, unquote

data_dir, psl_path = sys.argv[1], sys.argv[2]
months = sys.argv[3].split(",")

# --- Public Suffix List (ICANN / PRIVATE sections) ---
icann, private = set(), set()
wild_icann, wild_private, exc = set(), set(), set()
section = None
for line in open(psl_path, encoding="utf-8"):
    line = line.strip()
    if "BEGIN ICANN DOMAINS" in line: section = "i"
    elif "BEGIN PRIVATE DOMAINS" in line: section = "p"
    if not line or line.startswith("//"): continue
    rule = line.split()[0].encode("idna").decode() if not line.isascii() else line.split()[0]
    if rule.startswith("!"): exc.add(rule[1:]); continue
    tgt = (wild_icann if section == "i" else wild_private) if rule.startswith("*.") else (icann if section == "i" else private)
    tgt.add(rule[2:] if rule.startswith("*.") else rule)

def suffix(host, rules, wild):
    labels = host.split(".")
    best = labels[-1]
    for i in range(len(labels)):
        cand = ".".join(labels[i:])
        if cand in exc: return ".".join(labels[i+1:])
        if cand in rules: return cand
        if i + 1 < len(labels) and ".".join(labels[i+1:]) in wild: return cand
    return best

rows = []
for m in months:
    path = f"{data_dir}/{m[:4]}/{m}.csv"
    with open(path, encoding="utf-8", errors="replace") as f:
        for r in csv.DictReader(f):
            rows.append(r)

def entropy(s):
    c = collections.Counter(s); n = len(s)
    return -sum(v/n*math.log2(v/n) for v in c.values()) if n else 0

KEYWORDS = ["login","signin","verify","secure","account","update","support","wallet","auth","confirm","member","mypage"]
total = len(rows)
tld = collections.Counter(); kind = collections.Counter(); brands = collections.Counter()
priv = collections.Counter(); regdom = collections.Counter()
ip_host = 0; has_path = 0; path_kw = 0; brand_host = 0; brand_path = 0
rand_sub = 0; sub_present = 0; hosts=set()
brand_kw_cache = {}

def brand_tokens(desc):
    toks = [t for t in re.split(r"[^a-z0-9]+", desc.lower()) if len(t) >= 4]
    stop = {"japan","association","card","bank","corporation","company","online","group","service","services","holdings","financial"}
    return [t for t in toks if t not in stop]

for r in rows:
    url = r["URL"].strip()
    desc = (r.get("description") or "").strip()
    brands[desc] += 1
    try:
        u = urlsplit(url if "://" in url else "http://" + url)
        host = (u.hostname or "").rstrip(".").lower()
    except Exception:
        continue
    if not host: continue
    if re.fullmatch(r"[0-9.]+", host) or ":" in host:
        ip_host += 1; continue
    try:
        host_a = host.encode("idna").decode()
    except Exception:
        host_a = host
    hosts.add(host_a)
    t = host_a.rsplit(".", 1)[-1]
    tld[t] += 1
    kind["ccTLD" if len(t) == 2 and not t.startswith("xn--") else "gTLD"] += 1
    ps_i = suffix(host_a, icann, wild_icann)
    ps_p = suffix(host_a, private | icann, wild_private | wild_icann)
    reg = ".".join(host_a.split(".")[-(ps_i.count(".")+2):])
    regdom[reg] += 1
    if ps_p != ps_i and len(ps_p) > len(ps_i):
        priv[ps_p] += 1
    sub = host_a[:-len(reg)].rstrip(".")
    if sub:
        sub_present += 1
        first = sub.split(".")[0]
        if len(first) >= 6 and entropy(first) >= 2.8 and re.search(r"\d", first):
            rand_sub += 1
    p = unquote(u.path or "").lower()
    if p not in ("", "/"):
        has_path += 1
        words = set(re.split(r"[/\-_.]+", p))
        if words & set(KEYWORDS): path_kw += 1
    bt = brand_tokens(desc)
    hlabels = re.sub(r"[-.]", "", host_a[:-len(ps_i)])
    if bt and any(b in hlabels for b in bt): brand_host += 1
    if bt and any(b in p for b in bt): brand_path += 1

n = total - ip_host
print(f"期間: {months[0]}〜{months[-1]}  件数: {total}  (ホストがIP: {ip_host})")
print(f"ユニークなホスト: {len(hosts)}  ユニークな登録ドメイン: {len(regdom)}")
print("\n[gTLD/ccTLD]")
for k, v in kind.most_common(): print(f"  {k}: {v} ({v/n:.1%})")
print("\n[TLD 上位15]")
for k, v in tld.most_common(15): print(f"  .{k}: {v} ({v/n:.1%})")
print("\n[ccTLD 一覧(件数順)]")
print("  " + ", ".join(f".{k}:{v}" for k, v in tld.most_common() if len(k) == 2))
print(f"\n[privateサフィックス上] {sum(priv.values())} ({sum(priv.values())/n:.1%})")
for k, v in priv.most_common(10): print(f"  {k}: {v}")
print(f"\n[サブドメインあり] {sub_present} ({sub_present/n:.1%})  うちランダムらしい先頭ラベル: {rand_sub} ({rand_sub/n:.1%})")
print(f"[ホスト名に偽装先ブランドの語を含む(概算)] {brand_host} ({brand_host/n:.1%})")
print(f"[パスあり] {has_path} ({has_path/n:.1%})  パスに不審キーワード: {path_kw} ({path_kw/n:.1%})  パスにブランドの語: {brand_path} ({brand_path/n:.1%})")
print("\n[偽装先 上位10]")
for k, v in brands.most_common(10): print(f"  {k}: {v} ({v/total:.1%})")
print("\n[登録ドメインの使い回し 上位10]")
for k, v in regdom.most_common(10): print(f"  {k}: {v}")
top = regdom.most_common()
print(f"\n登録ドメイン1つあたりの平均URL数: {n/len(regdom):.1f}")
