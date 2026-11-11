"""文字列だけで付く点数(PLAN.md 6.5のうち、通信なしで評価できるルール)を、悪性と正常で比べる。

使い方:
  python3 -I string_score.py <このフォルダ> <データのフォルダ>
  データのフォルダの配置は README.md の「データの入手」と同じ(phish/repo、phish/psl.dat、crux/)。

評価するルール(配点はPLAN.md 6.5の既定。暫定を含む):
  name    keyword(+1、2個まで) / random_label(+3) / random_subdomain(+2) / long_label(+1) / path_keyword(+1)  上限+3
  brand   brand_contains(+3) / brand_lookalike(+4) / brand_in_path(+2)  最大値のみ
  infra   abused_tld_high(+2) / abused_tld_moderate(+1) / abused_hosting(+1)
評価しないルール(通信が必要):新しさ(登録日、証明書)、no_mx_spf、fast_flux、hold、減点(age_ge_5y、dnssec)

この測定のために仮に決めたもの(PLAN.mdでは未定。結果を読むときの注意は docs/research/string-score.md):
  - ブランドリスト:phase0のanalyze2.pyと同じ上位10ブランド。公式ドメインは下のOFFICIAL(仮)
  - 不審キーワード:PLAN.md 6.3に例示された8語。照合はブランドと同じ長さのルール(5文字以上は部分一致)
  - long_label:1つのラベルにハイフンが3個以上、または30文字以上
"""
import csv, gzip, sys, re, collections, functools
from urllib.parse import urlsplit, unquote

base, data = sys.argv[1], sys.argv[2]
sys.path.insert(0, base)
from randomcheck import label_hits
exec(open(base + "/psl_lib.py").read())
load_psl(data + "/phish/psl.dat")

KEYWORDS = ["login", "signin", "verify", "secure", "account", "update", "support", "wallet"]
TLD_HIGH = {"study", "cfd", "help", "top", "icu", "asia"}
TLD_MOD = {"info", "me", "cn", "shop", "co", "sbs", "cc"}
HOSTING = ["duckdns.org", "amazonaws.com"]
BRANDS = {
    "visa": (["visa"], ["visa.co.jp", "visa.com"]),
    "ekinet": (["ekinet", "jreast", "ekinetto"], ["eki-net.com", "jreast.co.jp"]),
    "ana": (["ana", "anamileage"], ["ana.co.jp"]),
    "apple": (["apple", "icloud", "appleid"], ["apple.com", "icloud.com"]),
    "saison": (["saison", "saisoncard"], ["saisoncard.co.jp"]),
    "smbc": (["smbc", "vpass", "smcc", "mitsuisumitomo"], ["smbc-card.com", "smbc.co.jp", "vpass.ne.jp"]),
    "jcb": (["jcb", "myjcb"], ["jcb.co.jp", "jcb.jp"]),
    "amazon": (["amazon", "amzn", "amazn"], ["amazon.co.jp", "amazon.com"]),
    "soumu": (["soumu", "mic"], ["soumu.go.jp"]),
    "nhk": (["nhk"], ["nhk.or.jp", "nhk.jp"]),
}
ALL_KW = {k for kws, _ in BRANDS.values() for k in kws}
ALL_OFFICIAL = {d for _, ds in BRANDS.values() for d in ds}


def lev(a, b, limit):
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > limit:
            return limit + 1
        prev = cur
    return prev[-1]


def substitutions(u):
    """0→o、1→l/i、rn→m、vv→w を当てた候補(元の文字列は含めない)"""
    out = set()
    for one in ("l", "i"):
        v = u.replace("0", "o").replace("1", one)
        out |= {v, v.replace("rn", "m"), v.replace("vv", "w"), v.replace("rn", "m").replace("vv", "w")}
    out.discard(u)
    return out


def kw_match(kw, unit, is_word):
    """キーワードの長さによるルール:5文字未満は単語の完全一致のみ、5文字以上は部分一致"""
    return (is_word and kw == unit) if len(kw) < 5 else kw in unit


@functools.lru_cache(maxsize=None)
def unit_brand(unit, is_word):
    """1つの単語(またはハイフンを除いたラベル全体)について、(含むブランドの集合, タイポ・文字置換で該当するブランドの集合)"""
    contains, look = set(), set()
    exact_other = unit in ALL_KW  # 別ブランドとの取り違えの防止
    cands = substitutions(unit)
    for name, (kws, _) in BRANDS.items():
        for kw in kws:
            if kw_match(kw, unit, is_word):
                contains.add(name)
            if exact_other:
                continue
            allowed = 0 if len(kw) <= 4 else 1 if len(kw) <= 7 else 2
            if any(kw_match(kw, c, is_word) for c in cands) and not kw_match(kw, unit, is_word):
                look.add(name)
            elif allowed and 0 < lev(unit, kw, allowed) <= allowed:
                look.add(name)
    return frozenset(contains), frozenset(look)


@functools.lru_cache(maxsize=None)
def unit_keywords(unit):
    return frozenset(k for k in KEYWORDS if k in unit)


def units_of(labels):
    words, wholes = set(), set()
    for l in labels:
        try:
            if l.startswith("xn--"):
                l = l.encode().decode("idna")
        except Exception:
            pass
        ws = [w for w in l.split("-") if w]
        words |= set(ws)
        if len(ws) > 1:
            wholes.add("".join(ws))
    return words, wholes - words


def score(host, path="", reg_only=False):
    """戻り値:(該当したルールの集合, {ブランドの扱い: 点数})。host は小文字のPunycode"""
    ps_i, ps_any = icann_suffix(host), any_suffix(host)
    if host in (ps_i, ps_any) and host == ps_i:
        return None
    private = ps_any != ps_i and host != ps_any
    reg = registrable(host, ps_i)
    rules = set()
    if private:
        if reg_only:
            return None
        labels = host[: -len(ps_any) - 1].split(".")
        if any(label_hits(l) for l in labels if l != "www"):
            rules.add("random_subdomain")
        if any(ps_any == h or ps_any.endswith("." + h) for h in HOSTING):
            rules.add("abused_hosting")
    else:
        reg_label = reg[: -len(ps_i) - 1]
        subs = [] if reg_only else [s for s in host[: -len(reg)].rstrip(".").split(".") if s]
        labels = subs + reg_label.split(".")
        if label_hits(reg_label):
            rules.add("random_label")
        if any(label_hits(l) for l in subs if l != "www"):
            rules.add("random_subdomain")
    tld = ps_i.rsplit(".", 1)[-1]
    if tld in TLD_HIGH:
        rules.add("abused_tld_high")
    elif tld in TLD_MOD:
        rules.add("abused_tld_moderate")
    if any(l.count("-") >= 3 or len(l) >= 30 for l in labels):
        rules.add("long_label")

    words, wholes = units_of(labels)
    kws, contains, look = set(), set(), set()
    for u, is_word in [(w, True) for w in words] + [(w, False) for w in wholes]:
        kws |= unit_keywords(u)
        c, l = unit_brand(u, is_word)
        contains |= c
        look |= l
    official_of = {n for n, (_, ds) in BRANDS.items() if reg in ds}
    contains -= official_of
    if reg in ALL_OFFICIAL and not private:
        look = set()
    look -= official_of
    if contains:
        rules.add("brand_contains")
    if look:
        rules.add("brand_lookalike")

    path_brand = False
    if path:
        p = unquote(path).lower()
        pwords = {w for w in re.split(r"[/\-_.]+", p) if w}
        if any(unit_keywords(w) for w in pwords):
            rules.add("path_keyword")
        pc = set()
        for w in pwords:
            pc |= unit_brand(w, True)[0]
        if pc - official_of:
            rules.add("brand_in_path")
    nkw = min(len(kws), 2)
    if nkw:
        rules.add("keyword")

    name = min(3, nkw + 3 * ("random_label" in rules) + 2 * ("random_subdomain" in rules)
               + ("long_label" in rules) + ("path_keyword" in rules))
    infra = 2 * ("abused_tld_high" in rules) + ("abused_tld_moderate" in rules) + ("abused_hosting" in rules)
    b_contains = max(3 * ("brand_contains" in rules), 2 * ("brand_in_path" in rules))
    b_all = max(b_contains, 4 * ("brand_lookalike" in rules))
    return rules, {"ブランドなし": name + infra, "ブランドを含む": name + infra + b_contains,
                   "ブランド(タイポ込み)": name + infra + b_all}, (words | wholes)


def phish_urls():
    for m in ["202607", "202608", "202609"]:
        for r in csv.DictReader(open(f"{data}/phish/repo/2026/{m}.csv", encoding="utf-8", errors="replace")):
            url = r["URL"].strip()
            u = urlsplit(url if "://" in url else "http://" + url)
            h = (u.hostname or "").lower().rstrip(".")
            if h and not re.fullmatch(r"[0-9.]+", h) and ":" not in h:
                try:
                    h = h.encode("idna").decode()
                except Exception:
                    pass
                yield h, u.path


def crux_hosts(ranks):
    with gzip.open(f"{data}/crux/data/country/jp/202609.csv.gz", "rt") as f:
        for r in csv.DictReader(f):
            if int(r["rank"]) in ranks:
                h = urlsplit(r["origin"]).hostname
                if h and not re.fullmatch(r"[0-9.]+", h):
                    yield h.lower().rstrip(".")


def reg_of(h):
    return registrable(h, icann_suffix(h))


RULES = ["random_label", "random_subdomain", "keyword", "long_label", "path_keyword", "abused_tld_high",
         "abused_tld_moderate", "abused_hosting", "brand_contains", "brand_lookalike", "brand_in_path"]
summary = {}


def report(title, items, reg_only=False, show_words=False):
    n, fired = 0, collections.Counter()
    dist = {k: collections.Counter() for k in ["ブランドなし", "ブランドを含む", "ブランド(タイポ込み)"]}
    look_words, cont_words = collections.Counter(), collections.Counter()
    for h, path in items:
        try:
            res = score(h, path, reg_only)
        except Exception:
            res = None
        if not res:
            continue
        rules, scores, units = res
        n += 1
        fired.update(rules)
        for k, v in scores.items():
            dist[k][v] += 1
        if show_words:
            for u in units:
                c, l = unit_brand(u, True)
                if l and "brand_lookalike" in rules:
                    look_words[u] += 1
                if c and "brand_contains" in rules:
                    cont_words[u] += 1
    print(f"\n## {title}(n={n})")
    print("  ルールの該当率: " + " / ".join(f"{r} {fired[r] / n:.1%}" for r in RULES if fired[r]))
    for k, d in dist.items():
        ge = lambda t: sum(v for s, v in d.items() if s >= t) / n
        print(f"  [{k}] 点数の分布: " + " ".join(f"{s}点:{d[s] / n:.1%}" for s in sorted(d))
              + f"\n      1点以上 {ge(1):.1%} / 2点以上 {ge(2):.1%} / 3点以上 {ge(3):.1%} / 4点以上(要確認) {ge(4):.1%} / 7点以上(高) {ge(7):.1%}")
        summary[(title, k)] = [ge(t) for t in (1, 2, 3, 4, 7)]
    if show_words:
        print("  タイポ・文字置換で該当した単語(上位20): " + ", ".join(f"{w}({c})" for w, c in look_words.most_common(20)))
        print("  ブランド名を含むで該当した単語(上位20): " + ", ".join(f"{w}({c})" for w, c in cont_words.most_common(20)))


urls = list(phish_urls())
p_hosts = sorted({h for h, _ in urls})
p_regs = sorted({reg_of(h) for h in p_hosts})
n_hosts = sorted(set(crux_hosts({1000000})))
n_regs = sorted({reg_of(h) for h in n_hosts})
t_hosts = sorted(set(crux_hosts({1000, 5000, 10000})))

report("悪性:URL(パスを含む)", urls)
report("悪性:ホスト(パスなし)", [(h, "") for h in p_hosts])
report("悪性:登録ドメインだけ", [(r, "") for r in p_regs], reg_only=True)
report("正常(50万〜100万位):ホスト", [(h, "") for h in n_hosts], show_words=True)
report("正常(50万〜100万位):登録ドメインだけ", [(r, "") for r in n_regs], reg_only=True)
report("正常(上位1万):ホスト", [(h, "") for h in t_hosts])

print("\n## 悪性÷正常(50万〜100万位)の比(ホスト、パスなし)")
for k in ["ブランドなし", "ブランドを含む", "ブランド(タイポ込み)"]:
    p, q = summary[("悪性:ホスト(パスなし)", k)], summary[("正常(50万〜100万位):ホスト", k)]
    print(f"  [{k}] " + " / ".join(f"{t}点以上 {a:.1%}÷{b:.1%}={a / b:.1f}倍" if b else f"{t}点以上 {a:.1%}÷0" for t, a, b in zip((1, 2, 3, 4, 7), p, q)))
