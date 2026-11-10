import csv, sys, re, math, collections
from urllib.parse import urlsplit, unquote
sys.path.insert(0, sys.argv[4])
exec(open(sys.argv[4] + "/psl_lib.py").read())

data_dir, psl_path, months = sys.argv[1], sys.argv[2], sys.argv[3].split(",")
load_psl(psl_path)

BRANDS = {
    "VISA JAPAN ASSOCIATION": ["visa"],
    "えきねっと": ["ekinet", "eki-net", "jreast", "ekinetto"],
    "ANA": ["ana", "anamileage", "ana-mileage"],
    "Apple Account": ["apple", "icloud", "appleid"],
    "SAISON CARD": ["saison", "saisoncard"],
    "三井住友カード": ["smbc", "vpass", "smcc", "mitsuisumitomo"],
    "JCB": ["jcb", "myjcb"],
    "Amazon": ["amazon", "amzn", "amazn"],
    "総務省": ["soumu", "mic"],
    "NHK": ["nhk"],
}
SUBST = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s"})
KEYWORDS = ["login","signin","verify","secure","account","update","support","wallet","auth","confirm","member","mypage"]

def entropy(s):
    c = collections.Counter(s); n = len(s)
    return -sum(v/n*math.log2(v/n) for v in c.values()) if n else 0

def brand_hit(text_words, joined, kws):
    for k in kws:
        if len(k) < 5:
            if k in text_words: return True
        elif k in joined or k in joined.translate(SUBST):
            return True
    return False

rows = []
for m in months:
    with open(f"{data_dir}/{m[:4]}/{m}.csv", encoding="utf-8", errors="replace") as f:
        rows += list(csv.DictReader(f))

per_dom = {}
url_stats = collections.Counter()
covered = 0
for r in rows:
    desc = (r.get("description") or "").strip()
    if desc not in BRANDS: continue
    covered += 1
    url = r["URL"].strip()
    u = urlsplit(url if "://" in url else "http://" + url)
    host = (u.hostname or "").lower().rstrip(".")
    if not host or re.fullmatch(r"[0-9.]+", host): continue
    try: host = host.encode("idna").decode()
    except Exception: pass
    ps_i, ps_p = icann_suffix(host), any_suffix(host)
    reg = registrable(host, ps_i)
    left = host[:-len(ps_p)].rstrip(".") if host.endswith(ps_p) and host != ps_p else host
    words = set(re.split(r"[-.]", left)); joined = re.sub(r"[-.]", "", left)
    p = unquote(u.path or "").lower(); pwords = set(re.split(r"[/\-_.]+", p))
    kws = BRANDS[desc]
    bh = brand_hit(words, joined, kws)
    bp = brand_hit(pwords, re.sub(r"[/\-_.]", "", p), kws)
    pk = bool(pwords & set(KEYWORDS))
    url_stats["brand_host"] += bh; url_stats["brand_path"] += bp; url_stats["path_kw"] += pk
    url_stats["brand_any"] += (bh or bp)
    d = per_dom.setdefault(reg, {"brand_host": False, "n": 0, "tld": reg.rsplit(".",1)[-1], "reg_label": reg[:-len(ps_i)-1]})
    d["n"] += 1; d["brand_host"] |= bh

print(f"対象: 上位10ブランドの {covered} 件(全 {len(rows)} 件の {covered/len(rows):.1%})")
print(f"[URL単位] ホスト名にブランド: {url_stats['brand_host']/covered:.1%}  パスにブランド: {url_stats['brand_path']/covered:.1%}  "
      f"どちらか: {url_stats['brand_any']/covered:.1%}  パスに不審キーワード: {url_stats['path_kw']/covered:.1%}")
nd = len(per_dom)
bd = sum(d["brand_host"] for d in per_dom.values())
print(f"[登録ドメイン単位] {nd} ドメイン中、ホスト名にブランドを含むもの: {bd} ({bd/nd:.1%})")

def looks_random(label):
    l = re.sub(r"[^a-z]", "", label)
    if len(l) < 4: return False
    vowels = sum(ch in "aeiou" for ch in l) / len(l)
    cons_run = max((len(m) for m in re.findall(r"[^aeiou]+", l)), default=0)
    return vowels < 0.25 or cons_run >= 5 or bool(re.search(r"\d", label))
rd = sum(looks_random(d["reg_label"]) for d in per_dom.values())
print(f"[登録ドメイン単位] 登録ドメインのラベルがランダムらしい(母音が少ない・子音が5連続以上・数字を含む): {rd} ({rd/nd:.1%})")
tl = collections.Counter(d["tld"] for d in per_dom.values())
print("[登録ドメイン単位のTLD 上位12] " + ", ".join(f".{k}:{v}({v/nd:.0%})" for k, v in tl.most_common(12)))
