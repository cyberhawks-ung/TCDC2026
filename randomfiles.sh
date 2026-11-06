#!/usr/bin/env bash

n=2000
dirs=("$HOME" /tmp /var/tmp /dev/shm)

for x in "${dirs[@]}"; do
    [[ -d "$x" && -w "$x" ]] || continue

    created=0

    while ((created < n)); do
        len=$((RANDOM % 30 + 1))

        rname=$(
            head -c 64 /dev/urandom |
            base64 |
            tr -dc 'a-zA-Z0-9' |
            cut -c "1-$len"
        )

        r="$x/$rname"

        # Create without overwriting existing files
        if (
            set -C
            {
                echo 'UNG is the BEST SMC!!!!'
                head -c 16 /dev/urandom | base64
            } > "$r"
        ) 2>/dev/null; then
            ((created++))
        fi
    done

    echo "Created $created files in $x"
done
