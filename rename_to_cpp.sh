for file in *.cpp
do
 mv "$file" "${file%.cpp}.c"
done
