import fte.encoder

regex = '^(a|b)+$'
fixed_slice = 512
input_plaintext = 'test'

fteObj = fte.encoder.RegexEncoder(regex, fixed_slice)

ciphertext = fteObj.encode(input_plaintext)
output_plaintext = fteObj.decode(ciphertext)

print 'regex='+regex
print 'fixed_slice='+str(fixed_slice)
print 'input_plaintext='+input_plaintext
print 'ciphertext='+ciphertext[:16]+'...'+ciphertext[-16:]
print 'output_plaintext='+output_plaintext[0]
