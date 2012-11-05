#! /bin/sh

for f in man[1-9]/*[1-9]
do
    tbl $f | eqn | groff -man | tee $f.ps | ps2pdf - > $f.pdf
done
