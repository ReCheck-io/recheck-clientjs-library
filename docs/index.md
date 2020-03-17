# Client Encryption API documentation
This is an encryption library created by ReCheck devs team. 

We are glad to receive any feedback you want to give us. 

A [Sequence Diagram](WebSequenceDiagram.md)

### Exported functions : 

#### debug: setDebugMode,
Setting the debug either true or false. 
  
#### init: init
Specify API token, host and blockchain network
  
#### login: login,
Returns a token that the user need in order to communicate with the server. 

#### loginWithChallenge: loginWithChallenge,
Returns a token that the user need in order to communicate with the server. Has a parameter _challenge_. When the user is using our service, upon login into the system there is going to be a QR code that you have to scan. That will create a link between the server and the GUI and you will be prompted to the GUI file manager. 

#### newKeyPair: newKeyPair 
Creates a key pairs and recovery phrase 

#### store: store
Encrypt, upload and register a file or any data 

#### open: open

#### share: share

#### validate: validate

#### prepare: prepare

#### decrypt: decrypt

#### poll: poll

#### select: select

#### selection: getSelected

#### prepareSelection: prepareSelection

#### execSelection: execSelection

---
### [Application layer](ApplicationLevel.md)  

---

### [Low level code](LowLevelCode.md)
 

