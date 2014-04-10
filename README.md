libfte
======


Overview
--------

Format-Transforming Encryption (FTE) is a cryptographic primitive explored in the paper *Protocol Misidentiﬁcation Made Easy with Format-Transforming Encryption* [1]. FTE allows a user to specify the format of their ouput ciphertexts using regular expressions. The libfte library implements the primitive presented in [1].

If you are interested in the *proxy system* that uses FTE to bypass DPI systems, please see [fteproxy](https://github.com/kpdyer/fteproxy).

Dependencies
------------

* Build tools (e.g., gcc, g++, etc.)
* GMP 5.1.x (https://gmplib.org/)

Installation
---------------------

To install libfte as a python module, do the following:

```python
python setup.py install
```

You can verify that libfte was built correctly by running:

```python
python setup.py test
```

To verify that libfte was installed correctly, try running one of the scripts in the ```examples/``` directory.


Example Usage
-------------

The following is an example usage of libfte.

```python
import fte.encoder

regex = '^(a|b)+$'
fixed_slice = 256
input_plaintext = 'test'

fteObj = fte.encoder.RegexEncoder(regex, fixed_slice)

ciphertext = fteObj.encode(input_plaintext)
output_plaintext = fteObj.decode(ciphertext)

print 'input_plaintext='+input_plaintext
print 'ciphertext='+ciphertext[:16]+'...'+ciphertext[-16:]
print 'output_plaintext='+output_plaintext
```

And the ouput of the above script would be the following, where the ouput ciphertext is a ```fixed_slice```-length string consisting of the characters ```a``` and ```b```, as defined by the ```regex``` variable.

```python
input_plaintext=test
ciphertext=aaaaaaaabaaaaaba...aabbbbbbbbaababb
output_plaintext=test
```


References
----------

[1] [Protocol Misidentification Made Easy with Format-Transforming Encryption](https://kpdyer.com/publications/ccs2013-fte.pdf)
    Kevin P. Dyer, Scott E. Coull, Thomas Ristenpart and Thomas Shrimpton 
