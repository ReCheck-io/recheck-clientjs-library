# Low-level codе
#### session25519 ( key1, key2 )
Uses two strings, in our case six words per key, to create four keys for the user's key pair.

---

#### getHash ( string )
Uses keccak256 (sha3) and returns the hash with the 0x prefix. 

---

#### getRequestHash ( requestBodyOrUrl )
In favor of better transaction validation, we decided to hash the content of every API call. This function is going to order the fields in JSON alphabetically and then hash it. This hash then will be added to the post request for back-end verification.  

---

#### encodeBase58Check ( src )
Encoding 32 byte[] into an address .

---

#### decodeBase58Check ( src )
Decoding into 32 byte[].

---

#### sign ( data, privateKey )
Function to cryptogrphically sign, in our case a document, with user's private key.

---

#### generateAkKeyPair ( passphrase )
Generates key pair, account, for AEternity blockchain. Takes as parameter the passphrase, which the user receives as back-up words or generates new words with the **diceware** method. Then uses the session25519 function with 6 words per key.
```
    key1 = words.slice(0, 6).join(' ');//0-5
    key2 = words.slice(6, 12).join(' ');//6-11

 else {
    key1 = diceware(6)
    key2 = diceware(6)
  }

  let phrase = `${key1} ${key2}`;
```
 Then uses these keys to generate the user's key pair, containing four different keys with the full phrase.
```
 case"ae":
    let publicSignBuffer = Buffer.from(keys.publicSignKey);
    secretSignBuffer = Buffer.from(keys.secretSignKey); // 64-bytes private key
    let address = `ak_${encodeBase58Check(publicSignBuffer)}`;
    return {
        address: address,
        publicKey: address,
        secretKey: secretSignBuffer.toString('hex'),
        publicEncKey: encodeBase58Check(publicEncBuffer),
        secretEncKey: secretEncBuffer.toString('hex'),
        phrase: phrase
    };

case  "eth":
    secretSignBuffer = Buffer.from(keys.secretKey); // 32-bytes private key
    let secretSignKey = `0x${secretSignBuffer.toString('hex')}`;
    let publicSignKey = EthCrypto.publicKeyByPrivateKey(secretSignKey);
    let publicAddress = EthCrypto.publicKey.toAddress(publicSignKey);

    return {
        address: publicAddress,
        publicKey: publicSignKey,
        secretKey: secretSignKey,
        publicEncKey: encodeBase58Check(publicEncBuffer),
        secretEncKey: secretEncBuffer.toString('hex'),
        phrase: phrase
    };
```

``` returns ``` *keyPair* object

---

#### akPairToRaw = (akPair) => {}

Converts and returns the Encryption key pair in raw bytes.

---

#### encrypt = (secretOrSharedKey, json, key) => {} 

Takes as input secret or shared key, a JSON object and a key. Using asymmetric public key encryption. 

Taken from [TweetNaCl Box example](https://github.com/dchest/tweetnacl-js/wiki/Examples)

```returns``` _Base64 encoded message_

---

#### decrypt = (secretOrSharedKey, messageWithNonce, key) => {}

Takes secret or shared key, encrypted message, and a key. Decrypts the message. 

Taken from [TweetNaCl Box example](https://github.com/dchest/tweetnacl-js/wiki/Examples)

```returns``` _JSON.parse(Base64 decrypted message)_ or _base64decryptedMessage_ if it comes from Java. 

---

#### encryptDataToPublicKeyWithKeyPair ( data, dstPublicEncKey, srcAkPair ) 
Encrypts the data, and returns and object with the cyphered data. 

``` 
encrypted = {
   
    payload: encryptedData,
    dstPublicEncKey: dstPublicEncKey,
    srcPublicEncKey: srcAkPair.publicEncKey
  
  } 
```

---

#### decryptDataWithPublicAndPrivateKey ( payload, srcPublicEncKey, secretKey )

Decrypts the data using TweetNacl box method and returns the decyphered data.

---

#### encryptDataWithSymetricKey = (data, key) => {}

Encrypts data with symmetric key using the TweetNaCl secret box methods. 

```returns``` _Base64 encrypted message_

---

#### decryptDataWithSymmetricKey = (messageWithNonce, key) => {}

Decrypts the messageWithNonce with symmetric key using the TweetNacl secret box method. 

```returns``` _UTF8 encoded decrypted message_

---

#### encryptFileToPublicKey ( fileData, dstPublicKey ) {}
This function creates sym key. Encrypts and returns an object with the cyphered data and the information to recreate the sym key, and decrypt the message if you have the rest of the information.

---

#### getFileUploadData ( fileObj, userChainId, userChainIdPubKey )
Encrypts the data with **encryptFileToPublicKey** method. Returns the following object
```
let fileUploadData = {
        userId: userChainId,
        docId: docChainId,
        requestId: requestId,
        requestType: requestType,
        requestBodyHashSignature: 'NULL',
        trailHash: trailHash,
        trailHashSignatureHash: getHash(trailHash),//TODO signature getHash(signMessage(trailHash, keyPair.secretKey))
        docName: fileObj.name,
        category: fileObj.category,
        keywords: fileObj.keywords,
        payload: encryptedFile.payload,
        encryption: {
            docHash: docOriginalHash,
            salt: encryptedFile.credentials.salt,
            passHash: syncPassHash,
            encryptedPassA: encryptedFile.credentials.encryptedPass,
            pubKeyA: encryptedFile.credentials.encryptingPubKey
        }
    };
```
This object is then hashed with **getRequestHash**. After that the hash is being added to the object before the creation of post request. 

```
    fileUploadData.requestBodyHashSignature = getRequestHash(fileUploadData);

```

---

#### processEncryptedFileInfo ( encryptedFileInfo, devicePublicKey, browserPrivateKey )
This function takes the file, gives it to the browser, the browser can now compose the full password and decrypt the file. 

```returns``` _An object with decrypted message_

---

#### getEndpointUrl ( action, appendix )

Gets the server route for the specific API call.

---

#### signMessage ( message, secretKey )
This function is to encapsulate the different ways to sing a message depending on the network. At the moment it is to sign with either Eth or AE sign. 

---

#### verifyMessage ( message, signature, pubKey )