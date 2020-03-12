Put the following code on https://www.websequencediagrams.com/ to get the **Sequence diagram**.


 
```
SenderBrowser->SenderBrowser: 0 onFile open/upload/send
SenderBrowser->SenderBrowser: 1 get doc original hash
SenderBrowser->SenderBrowser: 2 generate symetric pass
SenderBrowser->SenderBrowser: 3 get sym pass hash
SenderBrowser->SenderBrowser: 4 generate symetric pass salt
SenderBrowser->SenderBrowser: 5 encrypt file with concat sym hash(pass + salt)
SenderBrowser->SenderBrowser: 6 generate temp pub-priv keypair(A)
SenderBrowser->SenderBrowser: 7 encrypt sym pass(A+encrKey)
SenderBrowser->+Server: 8 upload doc orig. hash, encr. file, salt, sym pass hash, encr.pass(A+encrKey), temp pub key(A)
Server-->-SenderBrowser: 9 OK / doc original hash
RecBrowser->RecBrowser: 10 onDocOpenInViewer generate temp pub-priv keypair(B)
RecBrowser->+Server: 11 submit temp pub key(B) + original doc hash
Server-->-RecBrowser: 12 OK / doc original hash
RecBrowser->RecBrowser: 13 Display QR code (doc original hash)
RecBrowser->+Server: 14 poll for encrypted pass(B) by doc original hash
RecDevice->RecBrowser: 15 scan qr code for original hash
RecDevice->+Server: 16 get credentials by doc original hash from QR
Server-->-RecDevice: 17 encrypted sym pass(A+encrKey), encryptor pub key(A), temp pubkey(B)
RecDevice->RecDevice: 18 decrypt sym password(A+encrKey)
RecDevice->RecDevice: 19 get hash of decrypted password
RecDevice->RecDevice: 20 encrypt decrypted password with temp pubkey(B)
RecDevice->+Server: 21 submit encrypted pass(B) + pass hash + doc original hash
Server-->-RecDevice: 22 OK / doc original hash
Server->Server: 23 check decrypted pass hash
Server->-RecBrowser: 24 polling result = encrypted device pass(B) + salt + encrypted file
RecBrowser->RecBrowser: 25 decrypt password with temp priv key(B)
RecBrowser->RecBrowser: 26 decrypt file with hash(decrPass + salt)
RecBrowser->RecBrowser: 27 get decryptedDocHash
RecBrowser->+Server: 28 validate decryptedDocHash
Server-->-RecBrowser: 29 validation result
RecBrowser->RecBrowser: 30 push to fileviewer or saveAs
```

A fast link to it : 

_https://www.websequencediagrams.com/?lz=U2VuZGVyQnJvd3Nlci0-AAINOiAwIG9uRmlsZSBvcGVuL3VwbG9hZC9zZW5kCgAaHjEgZ2V0IGRvYyBvcmlnaW5hbCBoYXNoABcfMiBnZW5lcmF0ZSBzeW1ldHJpYyBwYXNzAE4fMwBoBXN5bQAoBQBFJDQAUhcgc2FsdACBPB81IGVuY3J5cHQgZmlsZSB3aXRoIGNvbmNhAH0GaGFzaCgAgQMFKwBJBSkAggsfNgCBagp0ZW1wIHB1Yi1wcml2IGtleXBhaXIoQQAiIDcAgQgJAIF7CChBK2VuY3JLZXkAbRErU2VydmVyOiA4IACDSAYAgxwJLgCDHQUsAIFZBS4AgVcFLACCCgUsAIJMDgAaBwBYDywAgTQJIGtleQCBLgZydmVyLS0-LQCERA85IE9LIC8AhAkTUmVjAIR-CQACCjogMTAgb25Eb2NPcGVuSW5WaWV3ZXIAghUgQikAQg0AgW0JMTEgc3VibWl0AIEiDkIpICsAhSAKZG9jAIUmCACBPAgAgQMNMgCBETEzIERpc3BsYXkgUVIgY29kZSAoAIYLEQCBGhg0IHBvbGwgZm9yAIRxCGVkAINgBkIpIGJ5AIIzFkRldmljZQCCOQ81IHNjYW4gcXIAfQZmb3IAHxoAgigKNgCHRgVjcmVkZW50aWFscwBgFSBmcm9tIFFSAIImDgCBAQY6IDEAhRsJZWQAhRIUAIRwBnlwdG9yAIQ5CwCESwoAgx4GAIFKDwBUCTggZGUAhXMOd29yZACFeQwAIhc5AIkhBQCBOgVvZgA9CACCVwd3b3JkAFoXMjAAh3oJACISAIgLBgCBHxoAhngJMgCFAgkAg0USKwCJQAogKwCKMhUAglITMgCEfxkAhwUHPgByCTMgY2hlY2sAgWQPAB8OAIVnDTIAhQAGaW5nIHJlc3VsdCA9AIUDC2QAhGkFAIEzC3NhbHQgKwCFJQtmaWxlAIdIGTI1AIM4CQCCMhQAigYHAIdEEACBEg02AIN6CQCLCwoAiwUFZGVjclAAiwIMAGwZNwCNLQYAg30IRG9jSACJBhAAgzIKOCB2YWxpZGF0ZQAgEgCIIBYyOQArCGlvbgCCPgcAiVoZMzAgcHVzaCB0bwCMYAV2AIluBm9yIHNhdmVBcw&s=default_
