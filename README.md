# RC4

This program encrypts/decrypts a file using a strengthened RC4 cipher.

Reinforcement consists in secretly deriving a key from a password : the PBKDF function.

DK = PBKDF2(HMAC_SHA256, Password, Salt, n)

* HMAC_SHA256 is the function used at each iteration
* Password is a string used to derive the key
* Salt is an 8-byte pseudo-random string
* n is the number of iterations to be performed

The result DK is the derived 32-byte key.

## Commands 

1. To compile : javac MonRC4.java
2. To encrypt a file : java MonRC4 -c path_of_the_encrypted_file encrypted_file_name
3. To decrypt a file : java MonRC4 -d path_of_the_decrypted_file decrypted_file_name

## Execution example

```
> echo "it's a strong cipher we got here" > test.txt

> java MonRC4 -c test.txt test2
Entrez un mot de passe : mommyitsastrongcipher
Le fichier chiffré test2.11fee7e627cc3981.rc4 a été généré avec succès.
Durée du traitement : 13 s

> java MonRC4 -d test2.11fee7e627cc3981.rc4 bad.txt
Veuillez entrer votre mot de passe : mommyitsaweakcipher
Veuillez entre le sel utilisé : 11fee7e627cc3981
Le fichier  a été déchiffré avec succès.
Durée du traitement : 13 s

> cat bad.txt
d*OqUNn$=-<uS5p

> java MonRC4 -d test2.11fee7e627cc3981.rc4 good.txt
Veuillez entrer votre mot de passe : mommyitsastrongcipher
Veuillez entre le sel utilisé : 11fee7e627cc3981
Le fichier  a été déchiffré avec succès.
Durée du traitement : 13 s

> cat good.txt
it's a strong cipher we got here

> diff -s test.txt good.txt
Files test.txt and good.txt are identical
```

## Credits

Small project with Aziz Jedidi
