# RC6-BLOCK-CIPHER

## RC6 Block cipher implementation was made for University Cipher course lectures. 

### Program arguments:

1. __-e__  Encryption mode with paths to text file and key file.
2. __-d__ Decryption mode with paths to encrypted text file and key file.

### commands:
1. __ java Main -e text key enc |  __text__ = file path to plaint text; __key__ = file path to key text; __enc__ = encrytped text file name.
2. __ java Main -d enc key output | __enc__ = encrytped text file name; __key__ = file path to key text; __ooutput__ = result in HEX representation;

__Command to save code changes:__ javac -d ./ src/Main.java src/rc6.java

__Command to perform encryption:__ java Main -e text key enc

__Command to perform decryption:__ java Main -d enc key output

Good converter from HEX, DEC to ASCII : https://www.branah.com/ascii-converter


