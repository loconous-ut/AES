# M2.5 Project: Advanced Encryption Standard (AES)
This project provides the implementation for AES.

## Compile
The project was created in a RHEL 8.5 OS machine using CPP (GCC) 8.5.0.  
To compile, run the following command:

    g++ -o aes aes.cpp

Alternatively, I made a quick makefile to compile. Quickly make the executable with:

    make

This will produce an executable with name of aes.  
You may then execute the program running the following command for output to the stdout:

    ./bin/aes

Alternatively, I would suggest to redirect the output to an output file, as follows:

    ./bin/aes > test/output

I have set up the output from appendix_c in test/appendix_c.txt file to ease the check of the solution with vimdiff.

## Resources

For all code and AES algorithms, I only used the FIPS 197 specification. I also used the Useful Arrays handout and Unit Tests for method checking.  
I will be honest by saying that I had to check some Stackoverflow and Wikipedia sites when attempting to get my bit manipulation and printing operations to work properly. 

## Test Cases

I should be able to pass all the test cases as provided in Appendix C. 

