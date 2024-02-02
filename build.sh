echo "Building..."
g++ *.cpp -o ./bin/jfa

if [ $? -eq 0 ]; then
    echo "Success!"
else
    echo "Failed!"
fi

