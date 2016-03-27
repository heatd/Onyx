for f in *.c; do
    cat $f | sed 's@//\(.*\)$@/*\1 */@' > $f
done
