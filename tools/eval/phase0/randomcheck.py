"""ランダム文字列の判定(方法B')の参照実装。計画書6.3の定義と一致させる。

定義:
  - 入力はラベル(ドット区切りの1要素、小文字)。xn-- で始まるラベル(Punycode)は判定しない
  - ASCII以外の文字を含むラベルは、ラベル全体を判定しない(Unicodeで渡しても
    Punycodeで渡しても同じ結果にするため。例:ドコモ-kvqlv も xn---kvqlv-2r4e9f0i も該当しない)
  - ハイフンで単語に区切り、各単語を判定する
  - 単語の長さ(英字と数字の合計)が5文字以上の場合のみ判定する
  - 母音は a, e, i, o, u の5文字。y は子音として扱う
  - 母音の比率 = 母音の数 / 英字の数(数字は分母に含めない)。英字が無い単語は該当しない
  - 子音の連続 = 英字の子音が途切れずに続く最大の長さ。数字は連続を途切れさせる
  - 「母音の比率が20%未満」または「子音の連続が5以上」なら、その単語は該当
  - ラベルのいずれかの単語が該当すれば、ラベルが該当
"""
import re

VOWELS = set("aeiou")


def word_hits(word: str) -> bool:
    if not word.isascii():
        return False
    letters = [c for c in word if "a" <= c <= "z"]
    digits = [c for c in word if "0" <= c <= "9"]
    if len(letters) + len(digits) < 5:
        return False
    if not letters:
        return False
    vowel_ratio = sum(c in VOWELS for c in letters) / len(letters)
    run = max((len(m) for m in re.findall(r"[b-df-hj-np-tv-z]+", word)), default=0)
    return vowel_ratio < 0.2 or run >= 5


def label_hits(label: str) -> bool:
    label = label.lower()
    if label.startswith("xn--") or not label.isascii():
        return False
    return any(word_hits(w) for w in label.split("-"))


def label_hits_unsplit(label: str) -> bool:
    """docs/research/phase0.md の初回測定で使った判定(ハイフンで区切らず、ラベル全体で判定)"""
    l = label.lower()
    if len(l) < 5:
        return False
    letters = [c for c in l if "a" <= c <= "z"]
    if not letters:
        return False
    vowel_ratio = sum(c in VOWELS for c in letters) / len(letters)
    run = max((len(m) for m in re.findall(r"[b-df-hj-np-tv-z]+", l)), default=0)
    return vowel_ratio < 0.2 or run >= 5
