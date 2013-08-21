all: test build

build:
	gcc -Wall -Wextra webm_sniff.c -o webm_sniff

test:
	./webm_sniff webm-samples/*

clean:
	rm webm_sniff
