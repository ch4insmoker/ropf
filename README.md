<h1>ROPF</h1>

## Desc
<p>ropf is very poorly written rop gadget finder</p>

## Todo
1. add support for 32 bit..
2. fix bug related to printing addresses
3. add support for instructions other then ret (bx, jcc...)

## Compiling
```
git clone --recursive https://github.com/ch4insmoker/ropf // recursive to include capstone lib
cd ropf
mkdir build
cd build
cmake ..
cmake --build .
```
