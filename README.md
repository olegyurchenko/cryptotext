# CRYPTOTEXT project #

CryptoText - programm for crypt/decrypt my notes

Previously, for such purposes, I used OpenSSL utility.

For crypt:
```
openssl enc -aes-256-cbc -a
```
For decrypt:
```
openssl enc -aes-256-cbc -a -d
```

But one day I could not decipher his notes, because of the fact that poor people have broken backward compatibility OpenSSL.

```
enter aes-256-cbc decryption password:
*** WARNING : deprecated key derivation used.
Using -iter or -pbkdf2 would be better.
bad decrypt
140136337404352:error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt:../crypto/evp/evp_enc.c:537:
```


