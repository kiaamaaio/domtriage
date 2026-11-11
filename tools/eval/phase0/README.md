# フェーズ0:実データの事前調査(2026年11月9日)

`docs/research/phase0.md`の数字を出したスクリプトと結果です。ツール本体には含めません。

## データの入手
- フィッシング:JPCERT/CC `JPCERTCC/phishurl-list`(GitHub)の `2026/202607〜202609.csv`
- 正常:`zakird/crux-top-lists`(GitHub)の `data/country/jp/202609.csv.gz`
- Public Suffix List:`publicsuffix/list` の `public_suffix_list.dat`

以下の配置を前提にしています(`BASE`はこのフォルダ)。
- `BASE/phish/repo/`(phishurl-listの取得先)
- `BASE/phish/psl.dat`
- `BASE/crux/data/country/jp/202609.csv.gz`

## ファイル
| ファイル | 内容 |
|---|---|
| `psl_lib.py` | Public Suffix List(ICANN/private)の簡易実装 |
| `analyze.py` | TLDの内訳、privateサフィックス、サブドメイン、パスなどの集計 |
| `analyze2.py` | 上位10ブランドでのブランド名の含有率、登録ドメイン単位の集計 |
| `compare.py` | 正常側(CrUX)との比較(判定方法A〜C、TLDの比率) |
| `remeasure.py` | 6.3の確定した定義(B')での測り直し |
| `remeasure_private.py` | サブドメイン(ホスト単位)とprivateサフィックス上のラベルの測定(元は別のセッションのレビューで作成。見出しを整理し、ホスト単位の集計を追加) |
| `randomcheck.py` | **ランダム文字列の判定の参照実装**(Goの実装と一致させる) |
| `string_score.py` | 文字列だけで付く点数(通信なしで評価できるルール)の、悪性と正常の比較(2026年11月11日に追加。結果は`docs/research/string-score.md`と`results/string_score.txt`)。引数は、このフォルダとデータのフォルダの2つ。ブランドリストなどは測定用の仮のもの |
| `check_age.sh` | 登録からの日数の測定(手元で実行。RDAPに接続できる環境が必要) |
| `check_cert.sh` | 証明書の発行時期の測定(手元で実行。crt.shに接続できる環境が必要) |
| `sample_domains.csv` | 9月分から抽出した40ドメイン |
| `results/` | 手元で測定した結果 |

## 実行例
```
python3 -I analyze.py phish/repo phish/psl.dat 202607,202608,202609
python3 -I analyze2.py phish/repo phish/psl.dat 202607,202608,202609 "$PWD"
python3 -I compare.py "$PWD"
python3 -I remeasure.py "$PWD"
python3 -I remeasure_private.py "$PWD"
python3 -I string_score.py "$PWD" "$PWD" > results/string_score.txt   # 約3分半
bash check_age.sh sample_domains.csv > results/age_result.csv
bash check_cert.sh results/age_result.csv > results/cert_result.csv
```
