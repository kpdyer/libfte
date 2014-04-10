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
