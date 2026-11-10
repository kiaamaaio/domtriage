#!/usr/bin/env bash
# フィッシングに使われたドメインの「報告時点での登録からの日数」を調べる(フェーズ0用)
# 使い方: bash check_age.sh sample_domains.csv > age_result.csv
# 必要なもの: curl, jq, GNU date(macOSの場合は gdate に置き換え)
# 1件ごとに2秒待つので、40件で2分弱かかります。

echo "domain,first_seen,registered,age_days_at_report,status"
tail -n +2 "$1" | while IFS=, read -r domain seen; do
  json=$(curl -sL --max-time 20 "https://rdap.org/domain/${domain}")
  reg=$(printf '%s' "$json" | jq -r '[.events[]? | select(.eventAction=="registration") | .eventDate][0] // empty' 2>/dev/null)
  if [ -n "$reg" ]; then
    age=$(( ( $(date -d "$seen" +%s) - $(date -d "${reg%%T*}" +%s) ) / 86400 ))
    echo "${domain},${seen},${reg%%T*},${age},ok"
  else
    code=$(printf '%s' "$json" | jq -r '.errorCode // empty' 2>/dev/null)
    echo "${domain},${seen},,,no_date${code:+_$code}"
  fi
  sleep 2
done
