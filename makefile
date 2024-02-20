# M2.5 Project: Advanced Encryption Standard (AES)
# Makefile
# Author: Luis A. Gonzalez Villalobos
# Date: 02/18/2024
# Simple Makefile

aes: src/aes.cpp
	gcc -o bin/aes src/aes.cpp

clean:
	rm -f bin/aes.o
