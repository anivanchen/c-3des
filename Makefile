default: run
compile main.out: main.o des.o sha.o
	@gcc -o main.out main.o des.o sha.o -lm -w
usage:
	@echo
	@echo "USAGE"
	@echo "=========="
	@echo "compile: compiles the program"
	@echo "run: 	runs main() of the program"
	@echo "encrypt: encrypts file listed using DES"
	@echo "decrypt: decrypts file listed using DES"
	@echo
	@echo "FLAGS"
	@echo "=========="
	@echo "input: 	input file name"
	@echo "output:  output file name"
	@echo "triple:  use triple DES algorithm, <true | false>"
main.o: main.c main.h des.h sha.h
	@gcc -c main.c -w
des.o: des.c main.h des.h
	@gcc -c des.c -w
sha.o: sha.c main.h sha.h
	@gcc -c sha.c -w
run: main.out
	@./main.out
encrypt: main.out
	@./main.out encrypt ${input} ${output} ${key} ${triple}
decrypt: main.out
	@./main.out decrypt ${input} ${output} ${key} ${triple}
sha: main.out
	@./main.out sha ${input}
test: main.out
	@./main.out test
clean:
	rm *.o main.out
format:
	clang-format -i -style=google *.c *.h
