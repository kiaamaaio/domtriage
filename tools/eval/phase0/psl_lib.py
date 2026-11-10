ICANN, PRIV, WI, WP, EXC = set(), set(), set(), set(), set()

def load_psl(path):
    section = None
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if "BEGIN ICANN DOMAINS" in line: section = "i"
        elif "BEGIN PRIVATE DOMAINS" in line: section = "p"
        if not line or line.startswith("//"): continue
        rule = line.split()[0]
        try: rule = ".".join(l.encode("idna").decode() for l in rule.split("."))
        except Exception: pass
        if rule.startswith("!"): EXC.add(rule[1:]); continue
        if rule.startswith("*."):
            (WI if section == "i" else WP).add(rule[2:])
        else:
            (ICANN if section == "i" else PRIV).add(rule)

def _suffix(host, rules, wild):
    labels = host.split(".")
    for i in range(len(labels)):
        cand = ".".join(labels[i:])
        if cand in EXC: return ".".join(labels[i+1:])
        if cand in rules: return cand
        if i + 1 < len(labels) and ".".join(labels[i+1:]) in wild: return cand
    return labels[-1]

def icann_suffix(host): return _suffix(host, ICANN, WI)
def any_suffix(host): return _suffix(host, ICANN | PRIV, WI | WP)
def registrable(host, ps):
    return ".".join(host.split(".")[-(ps.count(".") + 2):])
