#for f in *.h; do
 #   ccmtcnvt $f > $f-c89
#    rm -rf $f
#done
for file in *.h; do
    mv "$file" "`basename $file .h-c98`.h"
done
