libfte
======

Building/Installation
---------------------

To install libfte as a python module, do the following:

```
python setup.py install
```

Example Usage
-------------

```
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

```
input_plaintext=test
ciphertext=aaaaaaaabaaaaaba...aabbbbbbbbaababb
output_plaintext=test
```
