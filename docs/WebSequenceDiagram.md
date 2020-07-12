![protocol](protocol.png)

Put the following code on https://www.websequencediagrams.com/ to get the **Sequence diagram** if you want to make any changes. 
 
```
SenderDevice->SenderDevice: 0 onFile open/upload/send
SenderDevice->SenderDevice: 1 get data original hash
SenderDevice->SenderDevice: 2 generate symetric pass
SenderDevice->SenderDevice: 3 get sym pass hash
SenderDevice->SenderDevice: 4 generate symetric pass salt
SenderDevice->SenderDevice: 5 encrypt data with concat sym hash(pass + salt)
SenderDevice->SenderDevice: 6 generate temp pub-priv keypair(A)
SenderDevice->SenderDevice: 7 encrypt sym pass(A+encrKey)
SenderDevice->+Server: 8 upload data orig. hash, encr. file, salt, sym pass hash, encr.pass(A+encrKey), temp pub key(A)
Server-->-SenderDevice: 9 OK / data original hash
RecipientDevice->RecipientDevice: 10 onFileOpenInViewer generate temp pub-priv keypair(B)
RecipientDevice->+Server: 11 submit temp pub key(B) + data hash
Server-->-RecipientDevice: 12 OK / data hash
RecipientDevice->RecipientDevice: 13 Display QR code (data selection hash)
RecipientDevice->+Server: 14 poll for encrypted pass(B) by data hash
IdentityDevice->RecipientDevice: 15 scan qr code for data selection hash
IdentityDevice->+Server: 16 get credentials by data hash
Server-->-IdentityDevice: 17 encrypted sym pass(A+encrKey), encryptor pub key(A), temp pubkey(B)
IdentityDevice->IdentityDevice: 18 decrypt sym password(A+encrKey)
IdentityDevice->IdentityDevice: 19 get hash of decrypted password
IdentityDevice->IdentityDevice: 20 encrypt decrypted password with temp pubkey(B)
IdentityDevice->+Server: 21 submit encrypted pass(B) + pass hash + data hash
Server-->-IdentityDevice: 22 OK / data hash
Server->Server: 23 check decrypted pass hash
Server->-RecipientDevice: 24 polling result = encrypted device pass(B) + salt + encrypted file
RecipientDevice->RecipientDevice: 25 decrypt password with temp priv key(B)
RecipientDevice->RecipientDevice: 26 decrypt file with hash(decrPass + salt)
RecipientDevice->RecipientDevice: 27 get decryptedDataHash
RecipientDevice->+Server: 28 validate get original data hash
Server-->-RecipientDevice: 29 validation result
RecipientDevice->RecipientDevice: 30 push to fileviewer or saveAs
```

