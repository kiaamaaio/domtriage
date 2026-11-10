#!/usr/bin/env bash
# 初回の証明書が、フィッシングのリストに載る直前に発行されているかを調べる(フェーズ0用)
# 使い方: bash check_cert.sh age_result.csv > cert_result.csv
# 必要なもの: curl, jq, GNU date
# crt.shは遅く不安定なため、1件ごとに待ち時間を入れています。5分前後かかります。
#
# 出力の列:
#   first_cert    : 最初に発行された証明書の発行日(not_before)
#   last_before   : リストに載った日以前で、最も新しい証明書の発行日
#   days_last     : last_before からリストに載った日までの日数(小さいほど「使う直前に発行」)
#   certs_before  : リストに載った日以前に発行された証明書の件数(重複除去後)
#   status        : ok / no_cert(0件) / error(取得失敗)

fetch() {
  curl -s --max-time 60 "https://crt.sh/?q=$1&output=json"
}

echo "domain,first_seen,registered,first_cert,last_before,days_last,certs_before,status"
tail -n +2 "$1" | while IFS=, read -r domain seen reg age st; do
  a=$(fetch "${domain}"); sleep 3
  b=$(fetch "%25.${domain}"); sleep 3
  if ! printf '%s' "$a" | jq -e 'type=="array"' >/dev/null 2>&1 || \
     ! printf '%s' "$b" | jq -e 'type=="array"' >/dev/null 2>&1; then
    echo "${domain},${seen},${reg},,,,,error"; continue
  fi
  res=$(jq -rs --arg seen "$seen" '
    add
    | unique_by([.issuer_name, .serial_number])
    | map(.not_before[0:10])
    | {all: ., before: map(select(. <= $seen))}
    | [ (.all | min // ""), (.before | max // ""), (.before | length) ]
    | @tsv' <(printf '%s' "$a") <(printf '%s' "$b"))
  first=$(cut -f1 <<<"$res"); last=$(cut -f2 <<<"$res"); cnt=$(cut -f3 <<<"$res")
  if [ -z "$first" ]; then
    echo "${domain},${seen},${reg},,,,0,no_cert"; continue
  fi
  days=""
  if [ -n "$last" ]; then
    days=$(( ( $(date -d "$seen" +%s) - $(date -d "$last" +%s) ) / 86400 ))
  fi
  echo "${domain},${seen},${reg},${first},${last},${days},${cnt},ok"
done
