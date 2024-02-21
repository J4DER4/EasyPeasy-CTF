Automatic solver for picoCTF easypeasy, will also dump the hidden keychain used to decrypt given flag. Keychain needs to be looped around its max point to find the same key values as used in encrypting the flag in the beginning.
Works since:  XOR(x^k)=y <==> XOR(y^k)=x

Requirements: PWNlib, python3

Usage: 

Configure #VAR section in code to personal needs

To run:
$ python3 'Easy Peasy ctf solver.py'
