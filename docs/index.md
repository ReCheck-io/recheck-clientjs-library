# Client Encryption API documentation
This is an encryption library created by ReCheck devs team. 

We are glad to receive any feedback you want to give us. 

A [Sequence Diagram](WebSequenceDiagram.md)

# Application layer (high-level code)


### function init(_baseUrl, _token, _network) 
Initialises the token and challenge. Where token is optional. If the token is absent then by default the library is being used in the browser. 

The library is currently written so that it can use either Ethereum or Aethernity key pair. 

---

### async function login(keyPair)
Attemps to log in with the provided key pair. The function retunrs a newly created token.

---

### async function loginWithChallenge(challenge, keyPair)
Loggs in with a corresponded challenge code. The function is designed to be used on a mobile device. The challenge is represented as a QR code.  

---

### async function submitFile(fileObj, userChainId, userChainIdPubKey)
Upon execution of the function the following things happen. The file is being encrypted on the client side prior to which uploaded to the server. The server records info on the blockchain. The server returns the status code and receipt. 

``` returns``` _Example_

```

 { 
  status: 'OK',
  code: '200',
  blockchain: 'ae',
  action: 'upload',
  receipt: 
   { hash: 'th_xoWkCki44SyQhYDQYoyr6CdE8TkzsZFwrQLtKcXMNZspnoZBh',
     rawTx: 'tx_+QF2CwH4QrhAPrSS95Az/ZnL1CdHXu+Bpz238+T8W/Mwb2nKh/nqBpMqAeP63wmp3OWfXzT4IxJR6xUzs/mEnrZIZSJ6jmq9CbkBLfkBKisBoQEkhQ/kbCTuXjLXWs0RnlCVu9NN9PUf+s7T6zyA3VVpE4H4oQXSMfXgDxiL+RtAV1KovE/uEIfP1vvtSbgijixIfdg21wOHAZ6/bhxIAIMCdYMAgwGGoIQ7msoAuMkrEd8llA1rUVJUTiBTZWN1cmVkIERvY3VtZW50AQQweDU0NjYzMDdkNjdiZWRjM2JmMDBjN2NlNGEyMDQwNDBiY2Q3NTY2NDE2MGY2M2E2NmM5ZjQxZDdlYmQ1OGUwM2YGnwCgFklB6O51o3sXf/0VemPy1rAbpaGyNkqAnbKq2RU2TRR/AQQweDhCRkRGQ0RDQzkwRjY1RDQzMDlCMDBCQzE3MjUwMjZFNkNENDlBQzgyNEM4RDZGMjMzNjk5RDcxNUU1N0FGMkPH1SG5',
     result: 
      { callerId: 'ak_H5rDi9NViUebs6QFYYM2TKMifqtBCau77D48mF6AqJjuJA4tc',
        callerNonce: 248,
        contractId: 'ct_2ba9tN5TXAtQD4WwKiRkMhM2p5c5ML7wJt9Q8XrVpK8RbMhYUd',
        gasPrice: 1000000000,
        gasUsed: 2989,
        height: 161100,
        log: [],
        returnType: 'ok',
        returnValue: 'cb_/8CwV/U=' },
     decodedResult: true },
  docId: '0x5466307d67bedc3bf00c7ce4a204040bcd75664160f63a66c9f41d7ebd58e03f',
  userId: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5' }

```

---

### async function decryptWithKeyPair(userId, docChainId, keyPair)

Takes as parameters: 
- the userId
- the chain ID of the file
- the key pair of the user (currently AEternity supported only) 

Browser renders the docId as QR code and the user's device scans the QR. User device requests decryption info from server. After getting the decrypted password, it encrypts it again and sends it to the server. 

Returns the data for the file + encrypted password. 

---

### async function submitCredentials(docChainId, userChainId)

The browser creates a temporary key pair and submits a temporary public key. This key is used to decrypt the password coming from the mobile device. It expects document ID and the user's one for which the document is available.

---

### async function pollForFile(credentialsResponse, receiverPubKey)
Takes as parameters:
 
- credentialsResponce

_Example_
```
credentialsReponse: 
{
  userId:"0x23423432", 
  docId:"0x234234"
} 
```
- receiver Public Key

This function asks the server if there is a document shared with the user, so that it can fetch them. When the file becomes available (decrypted with the password provided by the mobile device) it is returned to the client as a result. 

---

### async function openFile(docChainId, userChainId, keyPair) 
Takes the user's credentials and scans for the requested file. If the user has permission (owns the file, or it has been shared to them) and the ile exists, then it is being decrypted and returned to the user. 


```return``` _Example_ where the **payload** has the contents of the file.
``` 
openResult { code: 200,
  status: 'unknown',
  action: 'download',
  docId: '0xc566de26a73d9795566ec393a3e5a775aea26fea9d3711a6ce399d4cb50990c8',
  ownerId: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5',
  hash: '0x0',
  name: 'secret',
  extension: '.pdf',
  receipt: '{"hash":"th_JhWaB2tTF7vc57W6KmodvoUafxRYGQK4xbP3teb5ZoyGsympn","rawTx":"tx_+QF2CwH4QrhA3OHYiMLbFCicYtuTyCP2Blr0xjqh75/6aKXQfshlXUt5Vv7D+Rxj7V2a14WY+9CkqEwOyMkpwWrzX4vswaTqAbkBLfkBKisBoQEkhQ/kbCTuXjLXWs0RnlCVu9NN9PUf+s7T6zyA3VVpE4H6oQXSMfXgDxiL+RtAV1KovE/uEIfP1vvtSbgijixIfdg21wOHAZ6/bhxIAIMCdzwAgwGGoIQ7msoAuMkrEd8llA1rUVJUTiBTZWN1cmVkIERvY3VtZW50AQQweGM1NjZkZTI2YTczZDk3OTU1NjZlYzM5M2EzZTVhNzc1YWVhMjZmZWE5ZDM3MTFhNmNlMzk5ZDRjYjUwOTkwYzgGnwCgFklB6O51o3sXf/0VemPy1rAbpaGyNkqAnbKq2RU2TRR/AQQweDhCRkRGQ0RDQzkwRjY1RDQzMDlCMDBCQzE3MjUwMjZFNkNENDlBQzgyNEM4RDZGMjMzNjk5RDcxNUU1N0FGMkN1KXDL","result":{"callerId":"ak_H5rDi9NViUebs6QFYYM2TKMifqtBCau77D48mF6AqJjuJA4tc","callerNonce":250,"contractId":"ct_2ba9tN5TXAtQD4WwKiRkMhM2p5c5ML7wJt9Q8XrVpK8RbMhYUd","gasPrice":1000000000,"gasUsed":2989,"height":161541,"log":[],"returnType":"ok","returnValue":"cb_/8CwV/U="},"decodedResult":true}',
  dateCreated: '2019-10-31T11:58:31.000Z',
  dateUpdated: '2019-10-31T11:58:31.000Z',
  category: 'OTHER',
  keywords: '',
  isEncrypted: true,
  userId: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5',
  payload: 'very secret file contents #674100 312321',
  encryption: {} }
```

---

### async function verifyFileDecryption(fileContents, userId, docId)

Given the contents of the file this function checks the hashed record on the blockchain and returns the file hash, the user ID. Returns _STATUS ERROR_ if the validation fails. 

---

### async function selectFiles(selectionType, files, recipients) 
This function is for the user to select several files which they want to manage (open/share) at a time. The result of this function is used in _getSelectedFiles_ to retrieve the list of files and users. Files and recepients are arrays. For each file ID corresponds a recepient ID. Using these two arrays one can design relations of the type M:M. 

_For example 3 files shared with 5 recepients._

```returns``` _qrCode_, where **qrCode** is 0x.. 

---

### async function getSelectedFiles(selectionHash)

Takes the selection hash and returns the list of files and recepients (userIDs).

---

### async function shareFile(docId, recipientId, keyPair)

Takes a document ID, a recipient ID and the sender's key pair. Decrypts the document password and then re-encrypts it with recipient's public key, so that they can access it via their private key. 


---

### registerHash(docChainId, requestType, targetUserId, keyPair, poll = false)

A function that registers the hash of a file directly on the blockchain. 

---

### verifyHash(docChainId, userId)

---

### async function prepareSelection(selection) 
Takes the selection hash, retrieves the list of files and users and submits for each file the public key used for the exchange of password.

---

### async function execSelection(selection, keyPair)

On the basis of the first parameter provided it will execute _Open_ or _Share_ on each file that is belonging to the selection.  

```retunrs``` _Example on OPEN_

```
exec result [ 
  { docId:'0xc49961a3755ef646beaf93bcd0fe207791ea0db3f59460dad16fb0fd23c94bce',
data:
  { code: 200,
    status: 'unknown',
    action: 'download',
    docId:
    '0xc49961a3755ef646beaf93bcd0fe207791ea0db3f59460dad16fb0fd23c94bce',
    ownerId: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5',
    hash: '0x0',
    name: 'secret',
    extension: '.pdf',
    receipt:
    '{"hash":"th_17swnB9gvGorAWrEYk6tJxhGhPH3Z9kQ7ioDVqqSs8EPgjUWQ","rawTx":"tx_+QF2CwH4QrhAlgYZFBs58BWWCu5wby1eKhWsuJB+8P8DrIVXG2ay3N7KSpEIdYq+C9vLsj1yw+0h++jX5n5niFkvX9T+fLz0C7kBLfkBKisBoQEkhQ/kbCTuXjLXWs0RnlCVu9NN9PUf+s7T6zyA3VVpE4H1oQXSMfXgDxiL+RtAV1KovE/uEIfP1vvtSbgijixIfdg21wOHAZ6/bhxIAIMCc4gAgwGGoIQ7msoAuMkrEd8llA1rUVJUTiBTZWN1cmVkIERvY3VtZW50AQQweGM0OTk2MWEzNzU1ZWY2NDZiZWFmOTNiY2QwZmUyMDc3OTFlYTBkYjNmNTk0NjBkYWQxNmZiMGZkMjNjOTRiY2UGnwCgFklB6O51o3sXf/0VemPy1rAbpaGyNkqAnbKq2RU2TRR/AQQweDhCRkRGQ0RDQzkwRjY1RDQzMDlCMDBCQzE3MjUwMjZFNkNENDlBQzgyNEM4RDZGMjMzNjk5RDcxNUU1N0FGMkPC47oQ","result":{"callerId":"ak_H5rDi9NViUebs6QFYYM2TKMifqtBCau77D48mF6AqJjuJA4tc","callerNonce":245,"contractId":"ct_2ba9tN5TXAtQD4WwKiRkMhM2p5c5ML7wJt9Q8XrVpK8RbMhYUd","gasPrice":1000000000,"gasUsed":2989,"height":160593,"log":[],"returnType":"ok","returnValue":"cb_/8CwV/U="},"decodedResult":true}',
    dateCreated: '2019-10-29T12:42:10.000Z',
    dateUpdated: '2019-10-29T12:42:10.000Z',
    category: 'OTHER',
    keywords: '',
    isEncrypted: true,
    userId: 'ak_wnSecLhxY8fD88JDsQTSskHcahNhjEqBhifxYtYZUSP4fWW3v',
    payload: 'very secret file contents #416510 3453454kk',
    encryption: {} } } 
    ]
```

---

# [Low level code](LowLevelCode.md)

--- 

## Exported functions : 

- debug: debugMode,

  
- init: init - Specify API token and API host
  
- login: login,
  
- loginWithChallenge: loginWithChallenge,

- newKeyPair: generateAkKeyPair - Create a keypair and recovery phrase 

- store: submitFile - Encrypt, upload and register a file or any data 

  
  /* Retrieve file - used in case of browser interaction */
- prepare: submitCredentials,
- decrypt: decryptWithKeyPair,
- poll: pollForFile,

  /* Retrieve fle - used in case of client interaction */
- open: openFile,

- validate: validateFile,
- select: selectFiles,
- selection: getSelectedFiles,
- share: shareFile,
- prepareSelection: prepareSelection,
- execSelection: execSelection
