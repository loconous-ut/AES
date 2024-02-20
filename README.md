# M2.5 Project: ADvanced Encryption Standard (AES)
This project provides the implementation for AES.

## Compile
The project was created in a RHEL 8.5 OS machine using CPP (GCC) 8.5.0.  
To compile, run the following command:

    g++ -o aes aes.cpp

Alternatively, I made a quick makefile to compile. Quickly make the executable with:

    make

This will produce an executable with name of aes.  
You may then execute the program running the following command for output to the stdout:

    ./aes

Alternatively, I would suggest to redirect the output to an output file, as follows:

    ./aes > output

## Resources

For all code and AES algorithms, I only used the FIPS 197 specification. Additionally, I utilized the Useful Arrays handout and Unit Tests for method checking. I will be honest by saying that I had to check some Stackoverflow when attempting to get my bit manipulation operations to work. 

## Test Cases

I should be able to pass all the test cases as provided in Appendix C. 

