echo "Building..."
if ! [ -d ./bin ]; then
mkdir ./bin
fi

g++ *.cpp -o ./bin/jfa "$@"

if [ $? -eq 0 ]; then
    echo "Success!"
else
    echo "Failed!"
fi

