#!/usr/bin/env bash
set -u

directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$directory/logs/oldasan"
if [ -f "$directory/asanfiltered.log" ]; then
    cp "$directory/asanfiltered.log" "$directory/logs/oldasan/"
fi
rm -f "$directory/asanfiltered.log"

mapfile -t sanitizer_logs < <(find "$directory/logs" -maxdepth 1 -type f -name 'asan*' -print | sort)
mapfile -t error_logs < <(find "$directory/logs" -maxdepth 1 -type f -name 'error[0-9]*' -print | sort)
runtime_logs=("${sanitizer_logs[@]}" "${error_logs[@]}")
if [ "${#runtime_logs[@]}" -eq 0 ]; then
    : >"$directory/asanfiltered.log"
    exit
fi

if [ "${#sanitizer_logs[@]}" -gt 0 ]; then
    grep -h -v "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior " "${sanitizer_logs[@]}" |
        grep -v ": runtime error: " |
        grep -v ": note: pointer points here" |
        grep -v "note: nonnull attribute specified here" |
        sed -E ':a;N;$!ba;s/\n/####/g' |
        sed -E 's/(==)[0-9]{2,}(==)/==????==/g;
                s/(0x)[0-9a-fA-F]{3,}/????/g;
                s/([Tt]hread T)[0-9]+/thread T???/g;
                s/(src_)[0-9]+/src_?/g;
                s/(run_)[0-9]+/run_?/g;
                s/\(BuildId: [0-9a-f]{15,40}\)/\(BuildId: ?????????????\)/g' |
        sed 's/####=================================================================/\n=================================================================/g' |
        sed -E 's/#{3,12}/####/g' |
        sort -u --parallel=6 |
        sed 's/####/\n/g' >>"$directory/asanfiltered.log" || true
fi

grep -h ": runtime error: " "${runtime_logs[@]}" |
    sed -E 's/(0x)[0-9a-fA-F]{3,}/????/g;
            s/(src_)[0-9]+/src_?/g;
            s/(run_)[0-9]+/run_?/g' |
    sort -u --parallel=6 >>"$directory/asanfiltered.log" || true

sort "$directory/asanfiltered.log" | grep "ERROR" | grep "AddressSanitizer" | uniq -c || true
sort "$directory/asanfiltered.log" | grep "WARNING" | uniq -c || true
printf "UBSan : "
grep -c ": runtime error: " "$directory/asanfiltered.log" || true
