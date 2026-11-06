#!/usr/bin/env bash
set -euo pipefail

# Files for plunt monitoring
OLD_PLUNT="pluntold.txt"
NEW_PLUNT="pluntnew.txt"

# Files for established monitoring
OLD_ESTAB="estabold.txt"
NEW_ESTAB="estabnew.txt"

# Ensure files exist
touch "$OLD_PLUNT" "$NEW_PLUNT" "$OLD_ESTAB" "$NEW_ESTAB"

FIRST_RUN=true

while true; do
    # Update old files with current new files for the next iteration
    cp "$NEW_PLUNT" "$OLD_PLUNT" 2>/dev/null || true
    cp "$NEW_ESTAB" "$OLD_ESTAB" 2>/dev/null || true

    # Capture fresh network state
    ss -plunt > "$NEW_PLUNT"
    ss -tpn state established > "$NEW_ESTAB"

    # Skip output on the very first iteration to avoid printing the initial state as "new"
    if $FIRST_RUN; then
        FIRST_RUN=false
        sleep 30
        continue
    fi

    # Identify lines present in new file but not in old file
    # -F: fixed strings, -f: read patterns from file, -v: invert match, -x: match whole lines
    new_plunt=$(grep -v -F -x -f "$OLD_PLUNT" "$NEW_PLUNT" | grep -v '^$' || true)
    new_estab=$(grep -v -F -x -f "$OLD_ESTAB" "$NEW_ESTAB" | grep -v '^$' || true)

    if [[ -n "$new_plunt" || -n "$new_estab" ]]; then
        echo -e "\n[$(date '+%Y-%m-%d %H:%M:%S')] New activity detected:"
        
        if [[ -n "$new_plunt" ]]; then
            echo "Plunt changes:"
            printf "%s\n" "$new_plunt"
        fi
        
        if [[ -n "$new_estab" ]]; then
            echo "Established connections:"
            printf "%s\n" "$new_estab"
        fi
        
        echo "----------------------------------------"
    fi
    
    sleep 30
done
