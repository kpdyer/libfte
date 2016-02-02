import regex2dfa
import fte.encoder

regex = '^(a|b)+$'
fixed_slice = 512
input_plaintext = 'test'

dfa = regex2dfa.regex2dfa(regex)
fteObj = fte.encoder.DfaEncoder(dfa, fixed_slice)

ciphertext = fteObj.encode(input_plaintext)
[output_plaintext, remainder] = fteObj.decode(ciphertext)

print 'input_plaintext='+input_plaintext
print 'ciphertext='+ciphertext[:16]+'...'+ciphertext[-16:]
print 'output_plaintext='+output_plaintext
