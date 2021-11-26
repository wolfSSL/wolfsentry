#!/bin/bash

POSIXLY_CORRECT=1

GEN_HTML=false
GEN_PDF=false
GEN_ALL=false
INSTALL_DOX=false

command -v g++
if [ $? -ne "0" ]; then
echo "Please install g++"
exit 1
fi

command -v cmake
if [ $? -ne "0" ]; then
echo "Please install cmake"
exit 1
fi

command -v git
if [ $? -ne "0" ]; then
echo "Please install git"
exit 1
fi

command -v make
if [ $? -ne "0" ]; then
echo "Please install make"
exit 1
fi

# Checking arguments and setting appropriate option variables

for var in $@
do
    case $var in
    -install)
        INSTALL_DOX=true
        ;;
    -html)
        GEN_HTML=true
        ;;
    -pdf)
        GEN_PDF=true
        ;;
    -all)
        GEN_ALL=true
        ;;
    esac
done

# Checking if doxygen is already installed
# True - doxygen from "which doxygen" is used to generate documentation
# False - clones doxygen Release_1_8_13 and ./build/bin/ added to PATH

if [ $INSTALL_DOX = true ] && [ ! "$(which doxygen)" ]; then
mkdir -p build
cd build
echo "cloning doxygen 1.8.13..."
git clone --depth 1 --branch Release_1_8_13 https://github.com/doxygen/doxygen
cmake -G "Unix Makefiles" doxygen/
make
cd ..
export PATH="./build/bin/:$PATH"
fi

#HTML GENERATION
if [ $GEN_HTML = true ] || [ $GEN_ALL = true ]; then
cp -r formats/html/* ./
echo "generating html..."
doxygen Doxyfile
rm Doxyfile
echo "finished generating html..."
echo "To view the html files use a browser to open the index.html file located at doc/html/index.html"
fi

#PDF GENERATION
if [ $GEN_PDF = true ] || [ $GEN_ALL = true ]; then
cp -r formats/pdf/* ./
echo "generating pdf..."
doxygen Doxyfile
cd latex/
make
mv refman.pdf ../
cd ..
rm -rf latex/
rm Doxyfile
echo "finished generating pdf..."
fi
