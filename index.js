const {box, secretbox, randomBytes} = require('tweetnacl');
const {decodeUTF8, encodeUTF8, encodeBase64, decodeBase64} = require('tweetnacl-util');
const diceware = require('diceware');
const session25519 = require('session25519');
const keccak256 = require('keccak256');
const bs58check = require('bs58check');
const axios = require('axios');
const nacl = require('tweetnacl');
const EthCrypto = require('eth-crypto');
const stringify = require('json-stable-stringify');


const newNonce = () => randomBytes(box.nonceLength);

const generateKey = () => encodeBase64(randomBytes(secretbox.keyLength));

let debug = true;

let baseUrl = 'http://localhost:3000';
let token = undefined;
let network = "eth"; //ae,eth

const requestId = 'ReCheck';

let browserKeyPair = undefined; // represents the browser temporary keypair while polling

(function setOrigin() {
    if (typeof window !== 'undefined'
        && !!window
        && !!window.location
        && !!window.location.origin) {
        init(window.location.origin,network);
    }
}());
const debugMode = (debugFlag) => {
    debug = debugFlag;

};
const log = (v1, v2) => {
    if (debug) {
        // console.log(`[${v1}]`, v2 ? v2 : '');
    }
};

async function _session25519(key1, key2) {
    return new Promise(resolve => {
        session25519(key1, key2, (err, result) => resolve(result));
    })
}

function isNullAny(...args) {
    for (let i = 0; i < args.length; i++) {
        let current = args[i];

        if (current == null //element == null covers element === undefined
            || (current.hasOwnProperty('length') && current.length === 0) // has length and it's zero
            || (current.constructor === Object && Object.keys(current).length === 0) // is an Object and has no keys
            || current.toString().toLowerCase() === 'null'
            || current.toString().toLowerCase() === 'undefined') {

            return true;
        }
    }
    return false;
}

function getHash(string) {
    return `0x${keccak256(string).toString('hex')}`;
}

function getRequestHash(requestBodyOrUrl) {
    let requestString = '';

    if (typeof requestBodyOrUrl === "object") {
        let resultObj = Object.assign({}, requestBodyOrUrl);

        if (!isNullAny(resultObj.payload)) {
            resultObj.payload = '';
        }

        if (!isNullAny(resultObj.requestBodyHashSignature)) {
            resultObj.requestBodyHashSignature = 'NULL';
        }

        requestString = stringify(resultObj).replace(/\s/g, "");
    } else {
        requestString = requestBodyOrUrl.replace(/([&|?]requestBodyHashSignature=)(.*?)([&]|$)/g, '$1NULL$3');
    }

    return getHash(requestString);
}

function sign(data, privateKey) {
    return nacl.sign.detached(Buffer.from(data), Buffer.from(privateKey));
}

function encodeBase58Check(src) {
    return bs58check.encode(Buffer.from(src));
}

function decodeBase58Check(src) {
    return bs58check.decode(src);
}

function hexStringToByte(src) {
    if (!src) {
        //TODO signature mismatch / arguments type do not match parameters
        return new Uint8Array();
    }

    let a = [];
    for (let i = 0, len = src.length; i < len; i += 2) {
        a.push(parseInt(src.substr(i, 2), 16));
    }

    return new Uint8Array(a);
}

async function generateAkKeyPair(passphrase) {

    let key1 = '';
    let key2 = '';

    if (passphrase) {
        const words = passphrase.split(' ');
        if (words.length < 12) {
            throw('Invalid passphrase. Must be 12 words long.');
        }
        key1 = words.slice(0, 6).join(' ');//0-5
        key2 = words.slice(6, 12).join(' ');//6-11
    } else {
        key1 = diceware(6);
        key2 = diceware(6);
    }

    let phrase = `${key1} ${key2}`;

    let keys = await _session25519(key1, key2);

    let publicEncBuffer = Buffer.from(keys.publicKey);
    let secretEncBuffer = Buffer.from(keys.secretKey);  // 32-bytes private key
    let secretSignBuffer;

    switch (network) {
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
    }
}

async function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

const akPairToRaw = (akPair) => {
    return {
        secretEncKey: hexStringToByte(akPair.secretEncKey),
        publicEncKey: new Uint8Array(decodeBase58Check(akPair.publicEncKey)),
    }
};

const encrypt = (
    secretOrSharedKey,
    json,
    key
) => {
    const nonce = newNonce();
    const messageUint8 = decodeUTF8(JSON.stringify(json));
    const encrypted = key
        ? box(messageUint8, nonce, new Uint8Array(key), new Uint8Array(secretOrSharedKey))
        : box.after(messageUint8, nonce, new Uint8Array(secretOrSharedKey));

    const fullMessage = new Uint8Array(nonce.length + encrypted.length);
    fullMessage.set(nonce);
    fullMessage.set(encrypted, nonce.length);

    return encodeBase64(fullMessage);//base64FullMessage
};

const decrypt = (
    secretOrSharedKey,
    messageWithNonce,
    key
) => {

    const messageWithNonceAsUint8Array = decodeBase64(messageWithNonce);
    const nonce = messageWithNonceAsUint8Array.slice(0, box.nonceLength);
    const message = messageWithNonceAsUint8Array.slice(
        box.nonceLength,
        messageWithNonce.length
    );

    const decrypted = key
        ? box.open(message, nonce, new Uint8Array(key), new Uint8Array(secretOrSharedKey))
        : box.open.after(message, nonce, new Uint8Array(secretOrSharedKey));

    if (!decrypted) {
        throw new Error('Decryption failed.');
    }

    const base64DecryptedMessage = encodeUTF8(decrypted);
    try {
        // from JS to JS 
        return JSON.parse(base64DecryptedMessage)
    } catch (e) {
        // from Java to JS 
        return base64DecryptedMessage
    }
};

async function encryptDataToPublicKeyWithKeyPair(data, dstPublicEncKey, srcAkPair) {
    if (!srcAkPair) {
        srcAkPair = await generateAkKeyPair(null); // create random seed
    }

    let destPublicEncKeyArray = new Uint8Array(decodeBase58Check(dstPublicEncKey));
    let rawSrcAkPair = akPairToRaw(srcAkPair);
    let dstBox = box.before(destPublicEncKeyArray, rawSrcAkPair.secretEncKey);
    let encryptedData = encrypt(dstBox, data);
    return {
        payload: encryptedData,
        dstPublicEncKey: dstPublicEncKey,
        srcPublicEncKey: srcAkPair.publicEncKey
    };//encrypted
}

function decryptDataWithPublicAndPrivateKey(payload, srcPublicEncKey, secretKey) {
    let srcPublicEncKeyArray = new Uint8Array(decodeBase58Check(srcPublicEncKey));
    let secretKeyArray = hexStringToByte(secretKey);
    let decryptedBox = box.before(srcPublicEncKeyArray, secretKeyArray);
    return decrypt(decryptedBox, payload);//decrypted
}

const encryptDataWithSymmetricKey = (data, key) => {
    const keyUint8Array = decodeBase64(key);

    const nonce = newNonce();
    log('data', data);
    const messageUint8 = decodeUTF8(data);
    const box = secretbox(messageUint8, nonce, keyUint8Array);

    const fullMessage = new Uint8Array(nonce.length + box.length);
    fullMessage.set(nonce);
    fullMessage.set(box, nonce.length);

    return encodeBase64(fullMessage);//base64FullMessage
};

const decryptDataWithSymmetricKey = (messageWithNonce, key) => {
    const keyUint8Array = decodeBase64(key);
    const messageWithNonceAsUint8Array = decodeBase64(messageWithNonce);
    const nonce = messageWithNonceAsUint8Array.slice(0, secretbox.nonceLength);

    const message = messageWithNonceAsUint8Array.slice(
        secretbox.nonceLength,
        messageWithNonce.length
    );
    const decrypted = secretbox.open(message, nonce, keyUint8Array);

    if (!decrypted) {
        throw new Error("Decryption failed");
    }

    return encodeUTF8(decrypted); //base64DecryptedMessage
};

async function encryptFileToPublicKey(fileData, dstPublicKey) {
    let fileKey = generateKey();
    let saltKey = generateKey();
    log('fileKey', fileKey);
    log('saltKey', saltKey);
    let symKey = encodeBase64(keccak256(fileKey + saltKey));
    log('symKey', symKey);
    log('fileData', fileData);
    let encryptedFile = encryptDataWithSymmetricKey(fileData, symKey);
    let encryptedPass = await encryptDataToPublicKeyWithKeyPair(fileKey, dstPublicKey);

    return {
        payload: encryptedFile,
        credentials: {
            syncPass: fileKey,
            salt: saltKey,
            encryptedPass: encryptedPass.payload,
            encryptingPubKey: encryptedPass.srcPublicEncKey
        }
    };
}

async function getFileUploadData(fileObj, userChainId, userChainIdPubKey) {
    let fileContents = fileObj.payload;
    let encryptedFile = await encryptFileToPublicKey(fileContents, userChainIdPubKey);
    let docOriginalHash = getHash(fileContents);
    let syncPassHash = getHash(encryptedFile.credentials.syncPass);
    let docChainId = getHash(docOriginalHash);
    let requestType = 'upload';
    let trailHash = getHash(docChainId + userChainId + requestType + userChainId);

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

    //TODO signature signMessage(getRequestHash(fileUploadData), keyPair.secretKey)
    fileUploadData.requestBodyHashSignature = getRequestHash(fileUploadData);

    return fileUploadData;
}

async function processEncryptedFileInfo(encryptedFileInfo, devicePublicKey, browserPrivateKey) {
    let decryptedSymPassword = decryptDataWithPublicAndPrivateKey(encryptedFileInfo.encryption.encryptedPassB, devicePublicKey, browserPrivateKey);
    log('Browser decrypts sym password', decryptedSymPassword);
    let fullPassword = encodeBase64(keccak256(decryptedSymPassword + encryptedFileInfo.encryption.salt));
    log('Browser composes full password', fullPassword);
    let decryptedFile = decryptDataWithSymmetricKey(encryptedFileInfo.payload, fullPassword);
    log('Browser decrypts the file with the full password', decryptedFile);
    let resultFileInfo = encryptedFileInfo;
    resultFileInfo.payload = decryptedFile;
    resultFileInfo.encryption = {};
    return resultFileInfo;
}

function getEndpointUrl(action, appendix) {
    let url = `${baseUrl}/${action}?noapi=1`;
    if (token) {
        url = `${baseUrl}/${action}?api=1&token=${token}`;
    }
    if (appendix) {
        url = url + appendix;
    }
    return url;
}

//////////////////////////////////////////////////////////// Application layer functions (higher level)

function init(_baseUrl, _token, _network) {    
    baseUrl = _baseUrl;
    if (_token)
        token = _token;
    // if (_network)
        // network = _network;
}

async function login(keyPair) {
    let getChallengeUrl = getEndpointUrl('login/challenge');
    let challengeResponse = await axios.get(getChallengeUrl);    
    if (!challengeResponse.data.challenge) {
        throw new Error('Unable to retrieve login challenge.');
    }
    return await loginWithChallenge(challengeResponse.data.challenge, keyPair);
}

function signMessage(message, secretKey) {    
    try {        
        switch (network) {
            
            case "ae":
                let signatureBytes = sign(Buffer.from(message), hexStringToByte(secretKey));
                return encodeBase58Check(signatureBytes);// signatureB58;

            case "eth":
                const messageHash = EthCrypto.hash.keccak256(message);
                return EthCrypto.sign(
                    secretKey,
                    messageHash
                );// signature;
        }
    } catch (ignored) {
        return false;
    }
}

function verifyMessage(message, signature, pubKey) {
    try {
        if (pubKey) {
            switch (network) {
                case "ae":
                    let verifyResult = nacl.sign.detached.verify(
                        new Uint8Array(Buffer.from(message)),
                        decodeBase58Check(signature),
                        decodeBase58Check(pubKey.split('_')[1])
                    );
                    if (verifyResult) {
                        return pubKey;
                    } else {
                        return false;
                    }

                case "eth":
                    return EthCrypto.recover(
                        signature,
                        EthCrypto.hash.keccak256(message)
                    ); //signer;
            }
        } else {
            return false;
        }
    } catch (ignored) {
        return false;
    }
}

async function loginWithChallenge(challenge, keyPair) {
    let signatureB58 = signMessage(challenge, keyPair.secretKey);
    console.log(signatureB58);
    
    let pubKey = keyPair.publicKey;    
    let payload = {
        action: 'login',
        pubKey: pubKey,
        pubEncKey: keyPair.publicEncKey,
        firebaseToken: 'notoken',
        challenge: challenge,
        challengeSignature: signatureB58,
        rtnToken:'notoken'
    };
    let loginUrl = getEndpointUrl('mobilelogin');
    let loginPostResult = await axios.post(loginUrl, payload);    
    if (loginPostResult.data.rtnToken) {
        token = loginPostResult.data.rtnToken;
        return loginPostResult.data.rtnToken;
    } else {
        throw new Error('Unable to retrieve API token.');
    }
}

async function submitFile(fileObj, userChainId, userChainIdPubKey) {
    log('Browser encrypts to receiver', fileObj, userChainId);
    let fileUploadData = await getFileUploadData(fileObj, userChainId, userChainIdPubKey);
    log('Browser submits encrypted data to API', fileUploadData);
    let submitUrl = getEndpointUrl('uploadencrypted');
    log('submitFile post', submitUrl);
    let submitRes = await axios.post(submitUrl, fileUploadData);
    log('Server returns result', submitRes.data);
    return submitRes.data;
}

async function decryptWithKeyPair(userId, docChainId, keyPair) {
    log('Browser renders the docId as qr code', docChainId);
    log('User device scans the qr', docChainId);
    log('User device requests decryption info from server', docChainId, userId);
    let requestType = 'download';
    let trailHash = getHash(docChainId + userId + requestType + userId);
    let trailHashSignatureHash = getHash(signMessage(trailHash, keyPair.secretKey));
    let query = `&userId=${userId}&docId=${docChainId}&requestId=${requestId}&requestType=${requestType}&requestBodyHashSignature=NULL&trailHash=${trailHash}&trailHashSignatureHash=${trailHashSignatureHash}`;
    let getUrl = getEndpointUrl('exchangecredentials', query);
    getUrl = getUrl.replace('NULL', signMessage(getRequestHash(getUrl), keyPair.secretKey));
    
    log('decryptWithKeyPair get request', getUrl);
    let serverEncryptionInfo = await axios.get(getUrl);
    
    log('Server responds to device with encryption info', serverEncryptionInfo.data);
    if (!serverEncryptionInfo.data.encryption || !serverEncryptionInfo.data.encryption.pubKeyB) {
        throw new Error('Unable to retrieve intermediate public key B.');
    }
    let decryptedPassword = decryptDataWithPublicAndPrivateKey(serverEncryptionInfo.data.encryption.encryptedPassA, serverEncryptionInfo.data.encryption.pubKeyA, keyPair.secretEncKey);    

    log('User device decrypts the sym password', decryptedPassword);
    let syncPassHash = getHash(decryptedPassword);
    let reEncryptedPasswordInfo = await encryptDataToPublicKeyWithKeyPair(decryptedPassword, serverEncryptionInfo.data.encryption.pubKeyB, keyPair);
    log('User device reencrypts password for browser', reEncryptedPasswordInfo);
    let devicePost = {
        docId: docChainId,
        userId: keyPair.address,
        encryption: {
            syncPassHash: syncPassHash,
            encryptedPassB: reEncryptedPasswordInfo.payload
        }
    };
    log('devicePost', devicePost);
    let postUrl = getEndpointUrl('exchangecredentials');
    log('decryptWithKeyPair post', postUrl);
    let serverPostResponse = await axios.post(postUrl, devicePost);
    log('User device POST to server encryption info', devicePost);
    log('Server responds to user device POST', serverPostResponse.data);
    return serverPostResponse.data;
}

async function submitCredentials(docChainId, userChainId) {
    if (!browserKeyPair) {
        browserKeyPair = await generateAkKeyPair(null);
    }
    log('Browser generates keypairB', browserKeyPair);
    let browserPubKeySubmit = {
        docId: docChainId,
        userId: userChainId,
        encryption: {
            pubKeyB: browserKeyPair.publicEncKey
        }
    };
    log('submit pubkey payload', browserPubKeySubmit);
    let browserPubKeySubmitUrl = getEndpointUrl('browsercredentials');
    log('browser poll post submit pubKeyB', browserPubKeySubmitUrl);
    let browserPubKeySubmitRes = await axios.post(browserPubKeySubmitUrl, browserPubKeySubmit);
    log('browser poll post result', browserPubKeySubmitRes.data);
    return browserPubKeySubmitRes.data;
}

async function pollForFile(credentialsResponse, receiverPubKey) {
    if (credentialsResponse.userId) {
        let pollUrl = getEndpointUrl('docencrypted', `&userId=${credentialsResponse.userId}&docId=${credentialsResponse.docId}`);
        for (let i = 0; i < 50; i++) {
            let pollRes = await axios.get(pollUrl);
            // log('browser poll result', pollRes.data)
            if (pollRes.data.encryption) {
                log('Server responds to polling with', pollRes.data);
                let decryptedFile = await processEncryptedFileInfo(pollRes.data, receiverPubKey, browserKeyPair.secretEncKey);
                let validationResult = await verifyFileDecryption(decryptedFile.payload, decryptedFile.userId, decryptedFile.docId);
                if (validationResult.status === 'ERROR') {
                    return validationResult;
                }
                return decryptedFile;
            } else {
                // log('waiting a bit')
                await sleep(1000);
            }
        }
        throw new Error('Polling timeout.');
    } else if (credentialsResponse.status === 'ERROR') {
        throw new Error(`Intermediate public key B submission error. Details:${credentialsResponse}`);
    } else {
        throw new Error(`Server did not return userId. Details:${credentialsResponse}`);
    }
}

async function openFile(docChainId, userChainId, keyPair) {
    let credentialsResponse = await submitCredentials(docChainId, userChainId);
    let scanResult = await decryptWithKeyPair(userChainId, docChainId, keyPair);
    if (scanResult.userId) {
        //polling server for pass to decrypt message
        return pollForFile(credentialsResponse, keyPair.publicEncKey);
    } else {
        throw new Error('Unable to decrypt file');
    }
}

async function verifyFileDecryption(fileContents, userId, docId) {
    let fileHash = getHash(fileContents);
    let validateUrl = getEndpointUrl('verify');

    let requestType = 'verify';
    let trailHash = getHash(docId + userId + requestType + userId);

    let postObj = {
        userId: userId,
        docId: docId,
        requestId: requestId,
        requestType: requestType,
        requestBodyHashSignature: 'NULL',
        trailHash: trailHash,
        trailHashSignatureHash: getHash(trailHash),//TODO signature getHash(signMessage(trailHash, keyPair.secretKey))
        encryption: {
            decryptedDocHash: fileHash
        }
    };

    //TODO signature signMessage(getRequestHash(postObj), keyPair.secretKey)
    postObj.requestBodyHashSignature = getRequestHash(postObj);

    let result = await axios.post(validateUrl, postObj);
    if (result.data.status === 'ERROR') {
        log('Unable to verify file.');
    } else {
        log('File contents validated.');
    }
    return result.data;
}

async function selectFiles(files, recipients) {
    let validateUrl = getEndpointUrl('selection');
    let result = await axios.post(validateUrl, {
        docsIds: files,
        usersIds: recipients
    });
    if (result.data.status === 'ERROR') {
        log('Unable to set selection.');
    } else {
        log('Selection set successfully.');
    }
    return result.data.selectionHash;
}

async function getSelectedFiles(selectionHash) {
    let getUrl = getEndpointUrl('selection', `&selectionHash=${selectionHash}`);
    log('getSelectedFiles get request', getUrl);
    let selectionResponse = await axios.get(getUrl);
    return selectionResponse.data;
}

async function shareFile(docId, recipientId, keyPair) {
    let getUrl = getEndpointUrl('shareencrypted', `&docId=${docId}&recipientId=${recipientId}`);
    log('shareencrypted get request', getUrl);
    let getShareResponse = await axios.get(getUrl);
    if (getShareResponse.data.docId === docId) {
        let recipientEncrKey = getShareResponse.data.encryption.recipientEncrKey;
        let encryptedPassA = getShareResponse.data.encryption.encryptedPassA;
        let pubKeyA = getShareResponse.data.encryption.pubKeyA;
        let decryptedPassword = decryptDataWithPublicAndPrivateKey(encryptedPassA, pubKeyA, keyPair.secretEncKey);
        let syncPassHash = getHash(decryptedPassword);
        let reEncryptedPasswordInfo = await encryptDataToPublicKeyWithKeyPair(decryptedPassword, recipientEncrKey, keyPair);
        let userId = keyPair.address;
        let recipientId = getShareResponse.data.recipientId;
        let docId = getShareResponse.data.docId;
        let requestType = 'share';
        let trailHash = getHash(docId + userId + requestType + recipientId);
        let trailHashSignatureHash = getHash(signMessage(trailHash, keyPair.secretKey));

        let createShare = {
            userId: userId,
            docId: docId,
            requestId: requestId,
            requestType: requestType,
            requestBodyHashSignature: 'NULL',
            trailHash: trailHash,
            trailHashSignatureHash: trailHashSignatureHash,
            recipientId: recipientId,
            encryption: {
                senderEncrKey: keyPair.publicEncKey,
                syncPassHash: syncPassHash,
                encryptedPassA: reEncryptedPasswordInfo.payload
            }
        };

        createShare.requestBodyHashSignature = signMessage(getRequestHash(createShare), keyPair.secretKey);

        let postUrl = getEndpointUrl('shareencrypted');
        let serverPostResponse = await axios.post(postUrl, createShare);
        log('Share POST to server encryption info', createShare);
        log('Server responds to user device POST', serverPostResponse.data);
        return serverPostResponse.data;
    }
    throw new Error('Unable to create share. Doc id mismatch.');
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function registerHash(docChainId, requestType, targetUserId, keyPair, poll = false) {
    let trailHash = getHash(docChainId + keyPair.address + requestType + targetUserId);
    let requestId = trailHash;
    let body = {
        docId: docChainId,
        userId: keyPair.address,
        requestId: trailHash,
        recipientId: targetUserId,
        requestType: requestType,
        requestBodyHashSignature: trailHash,
        trailHash: trailHash,
        trailHashSignatureHash: getHash(signMessage(trailHash, keyPair.secretKey)),
    };
    let postUrl = getEndpointUrl('chainregister');
    log('registerHash, ', body);
    let serverPostResponse = await axios.post(postUrl, body);
    log('Server responds to registerHash POST', serverPostResponse.data);
    let timeStep = 1000;
    let currentTime = 0;
    let maxTime = 20000;
    if (poll) {
        while (currentTime < maxTime) {
            await sleep(timeStep);
            let txList = (await verifyHash(docChainId, keyPair.address)).data;
            if (Array.isArray(txList)) {
                for (let i = 0; i < txList.length; i++) {
                    // console.log(txList[i].txStatus);
                    if (txList[i].requestId === requestId) {
                        if (txList[i].txStatus === 'complete') {
                            return txList[i].txReceipt;
                        } else if (txList[i].txStatus.includes('error')) {
                            return 'Receipt Unavailable. Transaction processing failed.';
                        }
                    }
                }
            }
            currentTime += timeStep;
        }
        return false;
    } else {
        return serverPostResponse.data;
    }
}

async function verifyHash(docChainId, userId, requestId) {
    let query = `&userId=${userId}&docId=${docChainId}`;
    if (!!requestId) {
        query += `&requestId=${requestId}`;
    }
    let getUrl = getEndpointUrl('chaincheck', query);
    log('query URL', getUrl);
    let serverResponse = await axios.get(getUrl);
    log('Server responds to verifyHash GET', serverResponse.data);
    return serverResponse.data;
}

async function prepareSelection(selection, keyPair) {
    let result = [];
    if (selection.indexOf(':') > 0) {               // check if we have a selection or an id
        let actionSelectionHash = selection.split(':');
        let action = actionSelectionHash[0];
        let selectionHash = actionSelectionHash[1];
        let selectionResult = await getSelectedFiles(selectionHash);
        log('selection result', selectionResult);
        if (selectionResult.selectionHash) {
            let recipients = selectionResult.usersIds;
            let files = selectionResult.docsIds;
            if (recipients.length !== files.length) {    // the array sizes must be equal
                throw new Error('Invalid selection format.');
            }
            for (let i = 0; i < files.length; i++) {  // iterate open each entry from the array
                if (action === 'o') {
                    //TODO keyPair is not defined?
                    if (keyPair.address !== recipients[i]) {
                        log('selection entry omitted', `${recipients[i]}:${files[i]}`);
                        continue;                           // skip entries that are not for that keypair
                    }
                    let credentialsResponse = await submitCredentials(files[i], recipients[i]);
                    result.push({docId: files[i], data: credentialsResponse});
                } else {
                    throw new Error('Unsupported selection operation code.');
                }
            }
        }
    } else {
        throw new Error('Missing selection operation code.');
    }
    return result;
}

async function execSelection(selection, keyPair) {
    let result = [];
    if (selection.indexOf(':') > 0) {               // check if we have a selection or an id
        let actionSelectionHash = selection.split(':');
        let action = actionSelectionHash[0];
        let selectionHash = actionSelectionHash[1];
        let selectionResult = await getSelectedFiles(selectionHash);
        log('selection result', selectionResult);
        if (selectionResult.selectionHash) {
            let recipients = selectionResult.usersIds;
            let files = selectionResult.docsIds;
            if (recipients.length !== files.length) {   // the array sizes must be equal
                throw new Error('Invalid selection format.');
            }
            for (let i = 0; i < files.length; i++) {  // iterate open each entry from the array

                switch (action) {
                    case 'o':
                        if (keyPair.address !== recipients[i]) {
                            log('selection entry omitted', `${recipients[i]}:${files[i]}`);
                            continue;                             // skip entries that are not for that keypair
                        }
                        if (keyPair.secretEncKey) {
                            log('selection entry added', `${recipients[i]}:${files[i]}`);
                            let fileContent = await openFile(files[i], keyPair.address, keyPair);
                            let fileObj = {
                                docId: files[i],
                                data: fileContent
                            };
                            result.push(fileObj);
                        } else {
                            let fileContent = await pollForFile({
                                docId: files[i],
                                userId: recipients[i]
                            }, keyPair.publicEncKey);
                            let fileObj = {
                                docId: files[i],
                                data: fileContent
                            };
                            result.push(fileObj);
                        }
                        break;

                    case's':
                        let shareResult = await shareFile(files[i], recipients[i], keyPair);
                        let shareObj = {
                            docId: files[i],
                            data: shareResult
                        };
                        result.push(shareObj);
                        break;

                    case 'mo':
                        if (keyPair.address !== recipients[i]) {
                            log('selection entry omitted', `${recipients[i]}:${files[i]}`);
                            continue;                      // skip entries that are not for that keypair
                        }
                        log('selection entry added', `${recipients[i]}:${files[i]}`);
                        let scanResult = await decryptWithKeyPair(recipients[i], files[i], keyPair);
                        let scanObj = {
                            docId: files[i],
                            data: scanResult
                        };
                        result.push(scanObj);
                        break;

                    default :
                        throw new Error('Unsupported selection operation code.');
                }
            }
        }
    } else {
        throw new Error('Missing selection operation code.');
    }
    return result;
}


module.exports = {

    debug: debugMode,

    /* Specify API token and API host */
    init: init,

    // login i login with challenge
    // login hammer 0(account) 0x.. (challenge code)
    // node hammer login 1 (second user's login)
    login: login,
    loginWithChallenge: loginWithChallenge,

    /* Create a keypair and recovery phrase */
    newKeyPair: generateAkKeyPair,

    /* Encrypt, upload and register a file or any data */
    //upload new file
    store: submitFile,

    /* Retrieve file - used in case of browser interaction */
    // submit credentials of the decrypting browser
    prepare: submitCredentials,
    // decrypt password and re-encrypt for decrypting browser
    decrypt: decryptWithKeyPair,
    // polling on the side of decrypting browser for encrypted file
    poll: pollForFile,

    /* Retrieve fle - used in case of client interaction */
    // node hammer open 0x...(docID) 0 (this account, different number = different account)
    // node hammer open 0x..(docId) 1 (user's credentials) 1 (user's credentials API)
    // hammer -i <acc.json> store <filename.txt>
    // hammer -i <acc.json> share <fileID> <recipientID>
    // hammer -i <acc.json> open <fileID>
    open: openFile,

    // verify file contents against a hash and its owner/recipient
    validate: verifyFileDecryption,

    // node hammer select-share 0x...(fileID) 2k_...(recipient) 0(sender) returns "s:qrCode"
    select: selectFiles,

    selection: getSelectedFiles,

    // node hammer share 0x..(docId) 1(user sender) 0(user receiver)
    share: shareFile,

    prepareSelection: prepareSelection,

    // node hammer exec o:0x...(selection hash)
    execSelection: execSelection,

    signMessage: signMessage,
    verifyMessage: verifyMessage,

    registerHash: registerHash,
    verifyHash: verifyHash
};
