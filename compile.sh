gcc -g -c trgencli.c -o trgencli.o
gcc -g trgencli.o -o trgencli.exe -L CommandParser/ -lcli
