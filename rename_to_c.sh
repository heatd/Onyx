for f in *.cpp; do
mv -- "$f" "${f%.cpp}.c"
done
