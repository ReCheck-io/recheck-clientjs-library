
# Application layer

#### init ( sourceBaseUrl, sourceToken, sourceNetwork = network ) 
Initialises the token and challenge. Where token is optional. If the token is absent then by default the library is being used in the browser. 

The library is currently written so that it can use either Ethereum or Aethernity key pair. 

---

#### login ( keyPair )
Attemps to log in with the provided key pair. The function returns a newly created token.

---

#### loginWithChallenge ( challenge, keyPair )
Loggs in with a corresponded challenge code. The function is designed to be used on a mobile device. The challenge is represented as a QR code.  

---

#### store ( fileObj, userChainId, userChainIdPubKey )
Upon execution of the function the following things happen. The file is being encrypted on the client side prior to which uploaded to the server. The server records info on the blockchain. The server returns the status code and receipt. 

---

#### decrypt ( userId, dataChainId, keyPair )

Browser renders the docId as QR code and the user's device scans the QR. User device requests decryption info from server. After getting the decrypted password, it encrypts it again and sends it to the server. 

Returns the data for the file + encrypted password. 

---

#### prepare ( dataChainId, userChainId )

The browser creates a temporary key pair and submits a temporary public key. This key is used to decrypt the password coming from the mobile device. It expects document ID and the user's one for which the document is available.

---

#### poll ( credentialsResponse, receiverPubKey )

This function asks the server if there is a file shared with the user, so that it can fetch them. When the file becomes available (decrypted with the password provided by the mobile device) it is returned to the client as a result. 

---

#### open ( dataChainId, userChainId, keyPair ) 
Takes the user's credentials and scans for the requested file. If the user has permission (owns the file, or it has been shared to them) and the ile exists, then it is being decrypted and returned to the user. 


```return``` _Example_ where the **payload** has the contents of the file.

---

#### validate ( fileContents, userId, dataId )

Given the contents of the file this function checks the hashed record on the blockchain and returns the file hash, the user ID. Returns _STATUS ERROR_ if the validation fails. 

---

#### selectFiles ( selectionType, files, recipients ) 
This function is for the user to select several files which they want to manage (open/share) at a time. The result of this function is used in _getSelected_ to retrieve the list of files and users. Files and recepients are arrays. For each file ID corresponds a recepient ID. Using these two arrays one can design relations of the type M:M. 

_For example 3 files shared with 5 recepients._

```returns``` _qrCode_ is a sha3/keccak256 hash containing the information

---

#### getSelected ( selectionHash )

Takes the selection hash and returns the list of files and recepients (userIDs).

---

#### share ( dataId, recipientId, keyPair )

Takes a document ID, a recipient ID and the sender's key pair. Decrypts the document password and then re-encrypts it with recipient's public key, so that they can access it via their private key. 


---

#### registerHash ( dataChainId, requestType, targetUserId, keyPair, poll = false )

A function that registers the hash of a file directly on the blockchain. 

---

#### verifyHash ( docChainId, userId )
Checks whether the hash is valid. 

---

#### prepareSelection ( selection, keyPair ) 
Takes the selection hash, retrieves the list of files and users and submits for each file the public key used for the exchange of password.

---

#### sign ( dataId, recipientId, keyPair )
Takes the dataID of the file and put a stamp (including timestamp) on it. By doing this the signer validates the presented information. 

---

#### execSelection ( selection, keyPair )

On the basis of the first parameter provided it will execute _'bo:' Browser Open_, _'mo:' Mobile Open_ _'sh:' Share_ or _'sg:' Sign_ on each file that is belonging to the selection.


