#!/bin/bash

TLDS=(cn jp kr kp mn tw hk mo in pk bd lk np bt mv af id my ph th vn sg mm kh la bn tl au nz pg fj sb vu ws to ki fm pw mh nr tv)

printf "%-6s %-6s %-16s %s\n" "TLD" "LEVEL" "STATE" "ISSUES"
printf "%-6s %-6s %-16s %s\n" "------" "-----" "----------------" "------"

for tld in "${TLDS[@]}"; do
  json=$(dnsviz probe "${tld}." 2>/dev/null | dnsviz grok 2>/dev/null)

  if [ -z "$json" ]; then
    printf "%-6s %-6s %-16s %s\n" ".$tld" "-" "ERROR" "no dnsviz output"
    continue
  fi

  delstatus=$(echo "$json" | jq -r ".\"${tld}.\".delegation.status // \"UNKNOWN\"" 2>/dev/null)
  badrrsig=$(echo "$json" | jq -r "[.. | .rrsig? // empty | .[] | select(.status != \"VALID\") | .status] | unique | join(\",\")" 2>/dev/null)

  if [ "$delstatus" = "INSECURE" ]; then
    printf "%-6s %-6s %-16s %s\n" ".$tld" "0" "UNSIGNED" "-"
    continue
  fi

  if [ "$delstatus" = "BOGUS" ] || [ -n "$badrrsig" ]; then
    reason="delegation=$delstatus"
    [ -n "$badrrsig" ] && reason="$reason;rrsig=$badrrsig"
    printf "%-6s %-6s %-16s %s\n" ".$tld" "1" "BROKEN/BOGUS" "$reason"
    continue
  fi

  algos=$(echo "$json" | jq -r ".\"${tld}.\".dnskey[]?.algorithm" 2>/dev/null | sort -u)
  issues=()

  while read -r a; do
    keylens=$(echo "$json" | jq -r ".\"${tld}.\".dnskey[]? | select(.algorithm==${a}) | .key_length" 2>/dev/null | sort -u)
    case "$a" in
      1|3|5|6|7) issues+=("deprecated-algorithm-$a") ;;
      10) issues+=("not-recommended-algorithm-$a") ;;
    esac
    if [ "$a" = "8" ] || [ "$a" = "5" ] || [ "$a" = "7" ] || [ "$a" = "1" ] || [ "$a" = "10" ]; then
      while read -r kl; do
        [ -n "$kl" ] && [ "$kl" -lt 2048 ] && issues+=("weak-rsa-keysize-${kl}bit")
      done <<< "$keylens"
    fi
  done <<< "$algos"

  dswarn=$(echo "$json" | jq -r "[.. | .warnings? // empty | .[] | .code] | unique | join(\",\")" 2>/dev/null)
  dserr=$(echo "$json" | jq -r "[.. | .errors? // empty | .[] | .code] | unique | join(\",\")" 2>/dev/null)
  [ -n "$dswarn" ] && issues+=("$dswarn")
  [ -n "$dserr" ] && issues+=("$dserr")

  crypto_bad=0
  for i in "${issues[@]}"; do
    case "$i" in
      deprecated-algorithm-*|not-recommended-algorithm-*|weak-rsa-keysize-*|*DIGEST_ALGORITHM_PROHIBITED*|*NONZERO_NSEC3_ITERATION_COUNT*)
        crypto_bad=1 ;;
    esac
  done

  joined=$(IFS=,; echo "${issues[*]}")

  if [ "${#issues[@]}" -eq 0 ]; then
    printf "%-6s %-6s %-16s %s\n" ".$tld" "4" "CONFORMANT" "-"
  elif [ "$crypto_bad" -eq 1 ]; then
    printf "%-6s %-6s %-16s %s\n" ".$tld" "2" "WEAK-CRYPTO" "$joined"
  else
    printf "%-6s %-6s %-16s %s\n" ".$tld" "3" "HYGIENE-GAPS" "$joined"
  fi
done
