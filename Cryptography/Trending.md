# TSIQQ, Trending

## Problem Description

All the existing hashing algorithms are dumb, why give me a fixed length? If I give you more input you should give me even more output, its only fair! I wrote a new hashing algorithm that improves on the best of the best (MD5)! Check it out and see if you can break it (you probably can't)!

Here's your hash: b18f21b19e0f86b22d218c86e182214b867b36212576b2617e8c03862d369e

the flag is all lowercase ascii characters, curly brackets and underscores

### Points

125

### Questionn type

Cryptography

### Learning available

https://qualifier.hackabit.com/learning/tsioq-trending

## Approach

### Understanding the "Hashencodecryption" Algorithm

We are given a python file named "hashbrown.py" that contains an algorithm to hashencodecrypt text.

The contents are:

```python
#!/usr/bin/python3

import sys
import hashlib
import random
import string

try:
    # get a five character string to use for randomness (lol)
    one_time_pad_or_something = ''.join(random.choices(string.digits, k=5))
    print(one_time_pad_or_something)
    
    # itterate over each character in the input
    for index,character in enumerate(sys.argv[1]):

        # get md5 hash of (that character plus minus pad)
        calculated_character = chr(ord(character) - int(one_time_pad_or_something[index % 5]))
        full_md5_hash = hashlib.md5(calculated_character.encode('ascii'))

        # take the first four characters and print them to the screen
        print(full_md5_hash.hexdigest()[0:2], end="")
    
    # new line at end of output
    print()

# verify that we got input in position
except IndexError: sys.exit("Usage: python3 hashbrown.py <plaintext>")
```

So there are certainly some things to digest here. To start, there's the OTP (one time pad), which will create a randomly generated string of 5 characters that
will shift each character in the input string. This is pretty nifty, but the issue is that each number in the OTP is a singly digit (0-9) and there's only 5 
numbers in the OTP. Guess how many characters of known plaintext we have? After creating the OTP, the program will loop through each char in the input string and
store a new char created by subtracting one of the OTP numbers from the ord() value of the current char in the string. Next, an md5 hash is created from the
OTP shifted character. After this, the hexadecimal value for the first character in the md5 hash is outputted without a tailing newline (this just makes it so
it looks like they concat the strings). Finally, a new line is printed. 

Something to note is that characters in the OTP are used in this pattern: 0, 1, 2, 3, 4, 0, 1, 2, 3, 4, 0... We know this because of the logic behind ```[index % 5]```.

An additional note: unless I'm being stupid, the comment ```# take the first four characters and print them to the screen``` is a lie, because it's two hex digits.
That was a pretty dirty move, Mr. Helix.

### Solving

Okay, so here's a quick list of things needed to get the flag text:

1. Get the OTP

2. Get the first two hex digits from the md5 hash of each possible character

3. Reverse the steps in the given program

#### The gameplan

So I know the first five characters of the flag (flag{), and that we have 5 one time pad ints that are applied in order from index 0-4

All I need to do is get the character that returns that first two hex chars of the md5 hash
for the first 5 characters, and then use some (very very very very...) basic algebra to find the full one time pad:

char - OTP = newChar

OTP = char - newChar

(Math!)

After this, it's just a matter of putting all of the potential characters into an array, and then looping through that array to create a dictionary of each char
mapped to it's corresponding first two hex digits of an md5 hash.

#### End of the gameplan

The code for my program that puts all of this together is:

```python
import hashlib
import re

# Every character from ord('_') - 9 (lowest possible char value) to ord('}') (highest possible char value)
ALL_CHARS = ['V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}']

def getAllHashes ():
    # The challenge states that the flag is all owercase ascii chars, curly brackets, and underscores.
    # With this information, I just need to write a function that gets the first two characters of every
    # hash for each of the allowed characters. This should (in theory) allow me to map each md5 character
    # to it's corresponding plaintext character with the OTP.
    allCharHashes = {}
    for i in ALL_CHARS:
        allCharHashes[hashlib.md5(i.encode('ascii')).hexdigest()[0:2]] = i

    return allCharHashes

def getTextWithOTP (cipherText, hashTable):
    # This function should go through each md5 hex for each character and get the corresponding plain
    # text character from the hash table
    eachChar = re.findall('..', cipherText)
    returnStr = ""
    for i in eachChar:
        if i in hashTable.keys():
            returnStr += hashTable[i]
        else:
            print("URGENT: NOT IN HASHTABLE")

    return returnStr

def getOTP (plainText, cipherText):
    # Uses a known plaintext attack (we know that the first five characters are flag{)
    # to get the one time pad. DOne by subtracting the plaintext ord value with the 
    # corresponding ciphertext ord value
    OTP = []
    cipherTextSplit = cipherText[0:len(plainText)]

    for i in range(len(plainText)):
        OTP.append(ord(plainText[i]) - ord(cipherTextSplit[i]))

    return OTP

def getPlaintext (OTPText, OTP):
    # The final function, just removes the one time pad from all the OTP Text
    returnStr = ""

    for i in range(len(OTPText)):
        returnStr += chr(ord(OTPText[i]) + OTP[i % 5])

    return returnStr

# Only do this if the program isn't being imported ("I exercise good programming practices")
if __name__ == '__main__':
    hashTable = getAllHashes()
    cipherText = "b18f21b19e0f86b22d218c86e182214b867b36212576b2617e8c03862d369e"
    textWithOTP = getTextWithOTP(cipherText, hashTable)
    OTP = getOTP("flag{", textWithOTP)
    flag = getPlaintext(textWithOTP, OTP)
    print(flag)
  ```
  
Esentially, at the top of the program I set up a constant array that stores each possible character ('V'-'}') that can be created by the OTP. I initially had a 
function that did that for me, but those values don't change, so I set it up as a constant after the computer did all of the necessary thinking for me.

After this, I set up a function to get each hash and return a dictionary with each character as a key to it's corresponding hash.

The textWithOTP function takes in the ciphertext and the previously created dictionary. It loops through each hex character and converts it to it's corresponding plain 
text character (with the OTP applied). It then returns a string of plaintext characters.

The getOTP function uses a string of known plaintext and then the string returned from getOTP(). It returns the OTP.

Finally, the getPlaintext function takes in the plaintext with the OTP still applied and the OTP and adds the ord() value of each character to its corresponding
OTP digit. It then appends the chr() value of that (this value is a plaintext character) to a string (this string is the flag) and returns it.

## Flag

flag{dont_roll_your_own_crypto}
