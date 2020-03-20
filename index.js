const {box, secretbox, randomBytes} = require('tweetnacl');
const {decodeUTF8, encodeUTF8, encodeBase64, decodeBase64} = require('tweetnacl-util');
const diceware = require('diceware');
const session25519 = require('session25519');
const keccak256 = require('keccak256');
const bs58check = require('bs58check');
const axios = require('axios');
const nacl = require('tweetnacl');
const ethCrypto = require('eth-crypto');
const stringify = require('json-stable-stringify');

let debug = true;

let baseUrl = 'http://localhost:3000';
let token = null;
let network = "ae"; //ae,eth

const requestId = 'ReCheck';

let browserKeyPair = undefined; // represents the browser temporary keypair while polling

const newNonce = () => randomBytes(box.nonceLength);

const generateKey = () => encodeBase64(randomBytes(secretbox.keyLength));

const log = (message, params) => {
    if (debug) {
        console.log(`[${message}]`, params ? params : '');
    }
};

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
        let resultObj = JSON.parse(JSON.stringify(requestBodyOrUrl));

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

function encodeBase58Check(input) {
    return bs58check.encode(Buffer.from(input));
}

function decodeBase58Check(input) {
    return bs58check.decode(input);
}

function hexStringToByte(hexString) {
    if (isNullAny(hexString)) {
        return new Uint8Array();
    }

    let result = [];
    for (let i = 0; i < hexString.length; i += 2) {
        result.push(parseInt(hexString.substr(i, 2), 16));
    }

    return new Uint8Array(result);
}

async function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function encryptDataToPublicKeyWithKeyPair(data, dstPublicEncKey, srcAkPair) {
    if (isNullAny(srcAkPair)) {
        srcAkPair = await newKeyPair(null); // create random seed
    }

    let destPublicEncKeyArray = new Uint8Array(decodeBase58Check(dstPublicEncKey));
    let rawSrcAkPair = akPairToRaw(srcAkPair);
    let dstBox = box.before(destPublicEncKeyArray, rawSrcAkPair.secretEncKey);
    let encryptedData = encryptData(dstBox, data);

    return {
        payload: encryptedData,
        dstPublicEncKey: dstPublicEncKey,
        srcPublicEncKey: srcAkPair.publicEncKey
    };//encrypted


    function akPairToRaw(akPair) {
        return {
            secretEncKey: hexStringToByte(akPair.secretEncKey),
            publicEncKey: new Uint8Array(decodeBase58Check(akPair.publicEncKey)),
        }
    }

    function encryptData(secretOrSharedKey, json, key) {
        const nonce = newNonce();
        const messageUint8 = decodeUTF8(JSON.stringify(json));

        const encrypted = key
            ? box(messageUint8, nonce, new Uint8Array(key), new Uint8Array(secretOrSharedKey))
            : box.after(messageUint8, nonce, new Uint8Array(secretOrSharedKey));

        const fullMessage = new Uint8Array(nonce.length + encrypted.length);
        fullMessage.set(nonce);
        fullMessage.set(encrypted, nonce.length);

        return encodeBase64(fullMessage);//base64FullMessage
    }
}

function decryptDataWithPublicAndPrivateKey(payload, srcPublicEncKey, secretKey) {
    let srcPublicEncKeyArray = new Uint8Array(decodeBase58Check(srcPublicEncKey));
    let secretKeyArray = hexStringToByte(secretKey);
    let decryptedBox = box.before(srcPublicEncKeyArray, secretKeyArray);

    return decryptData(decryptedBox, payload);//decrypted


    function decryptData(secretOrSharedKey, messageWithNonce, key) {
        const messageWithNonceAsUint8Array = decodeBase64(messageWithNonce);
        const nonce = messageWithNonceAsUint8Array.slice(0, box.nonceLength);
        const message = messageWithNonceAsUint8Array.slice(
            box.nonceLength,
            messageWithNonce.length
        );

        const decrypted = key
            ? box.open(message, nonce, new Uint8Array(key), new Uint8Array(secretOrSharedKey))
            : box.open.after(message, nonce, new Uint8Array(secretOrSharedKey));

        if (isNullAny(decrypted)) {
            throw new Error('Decryption failed.');
        }

        const base64DecryptedMessage = encodeUTF8(decrypted);

        return JSON.parse(base64DecryptedMessage);
    }
}

async function getFileUploadData(fileObj, userChainId, userChainIdPubKey) {
    let fileContents = fileObj.payload;
    let encryptedFile = await encryptFileToPublicKey(fileContents, userChainIdPubKey);
    let dataOriginalHash = getHash(fileContents);
    let syncPassHash = getHash(encryptedFile.credentials.syncPass);
    let dataChainId = getHash(dataOriginalHash);
    let requestType = 'upload';
    let dataExtraArgs = fileObj.extra;

    if (isNullAny(dataExtraArgs)) {
        dataExtraArgs = [];
    }

    //TODO add JSON.stringify(dataExtraArgs)
    let trailHash = getHash(dataChainId + userChainId + requestType + userChainId);

    let fileUploadData = {
        userId: userChainId,
        dataId: dataChainId,
        requestId: requestId,
        requestType: requestType,
        requestBodyHashSignature: 'NULL',
        trailHash: trailHash,
        trailHashSignatureHash: getHash(trailHash),//TODO signature getHash(signMessage(trailHash, keyPair.secretKey))
        dataName: fileObj.dataName,
        dataExtension: fileObj.dataExtension,
        category: fileObj.category,
        keywords: fileObj.keywords,
        payload: encryptedFile.payload,
        encryption: {
            dataOriginalHash: dataOriginalHash,
            salt: encryptedFile.credentials.salt,
            passHash: syncPassHash,
            encryptedPassA: encryptedFile.credentials.encryptedPass,
            pubKeyA: encryptedFile.credentials.encryptingPubKey
        }
    };

    //TODO signature signMessage(getRequestHash(fileUploadData), keyPair.secretKey)
    fileUploadData.requestBodyHashSignature = getRequestHash(fileUploadData);

    return fileUploadData;


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


        function encryptDataWithSymmetricKey(data, key) {
            const keyUint8Array = decodeBase64(key);

            const nonce = newNonce();
            log('data', data);
            const messageUint8 = decodeUTF8(data);
            const box = secretbox(messageUint8, nonce, keyUint8Array);

            const fullMessage = new Uint8Array(nonce.length + box.length);
            fullMessage.set(nonce);
            fullMessage.set(box, nonce.length);

            return encodeBase64(fullMessage);//base64FullMessage
        }
    }
}

function getEndpointUrl(action, appendix) {
    let url = `${baseUrl}/${action}?noapi=1`;

    if (!isNullAny(token)) {
        url = `${baseUrl}/${action}?api=1&token=${token}`;
    }

    if (!isNullAny(appendix)) {
        url = url + appendix;
    }

    return url;
}

////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////// Application layer functions (higher level)
////////////////////////////////////////////////////////////

(function setOrigin() {
    if (typeof window !== 'undefined'
        && window
        && window.location
        && window.location.origin) {
        init(window.location.origin);
    }
}());

const setDebugMode = (debugFlag) => {
    debug = debugFlag;
};

function init(sourceBaseUrl, sourceToken, sourceNetwork = network) {
    baseUrl = sourceBaseUrl;

    if (!isNullAny(sourceToken)) {
        token = sourceToken;
    }

    if (!isNullAny(sourceNetwork)) {
        network = sourceNetwork;
    }
}

async function login(keyPair) {
    let getChallengeUrl = getEndpointUrl('login/challenge');

    let challengeResponse = (await axios.get(getChallengeUrl)).data;

    if (isNullAny(challengeResponse.data.challenge)) {
        throw new Error('Unable to retrieve login challenge.');
    }

    return await loginWithChallenge(challengeResponse.data.challenge, keyPair);
}

async function loginWithChallenge(challenge, keyPair) {
    let payload = {
        action: 'login',
        pubKey: keyPair.publicKey,
        pubEncKey: keyPair.publicEncKey,
        firebase: 'notoken',
        challenge: challenge,
        challengeSignature: signMessage(challenge, keyPair.secretKey),//signatureB58
        rtnToken: 'notoken'
    };

    let loginUrl = getEndpointUrl('login/mobile');

    let loginPostResult = (await axios.post(loginUrl, payload)).data;

    if (isNullAny(loginPostResult.data.rtnToken)) {
        throw new Error('Unable to retrieve API token.');
    }

    token = loginPostResult.data.rtnToken;
    return token;
}

async function newKeyPair(passPhrase) {

    let key1 = '';
    let key2 = '';

    if (!isNullAny(passPhrase)) {
        const words = passPhrase.split(' ');

        if (words.length !== 12) {
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

    let publicEncBufferEncoded = encodeBase58Check(Buffer.from(keys.publicKey));
    let secretEncBufferHex = Buffer.from(keys.secretKey).toString('hex');  // 32-bytes private key
    let secretSignBuffer;
    switch (network) {
        case"ae":
            let publicSignBuffer = Buffer.from(keys.publicSignKey);
            secretSignBuffer = Buffer.from(keys.secretSignKey).toString('hex'); // 64-bytes private key
            let address = `ak_${encodeBase58Check(publicSignBuffer)}`;

            return {
                address: address,
                publicKey: address,
                secretKey: secretSignBuffer,
                publicEncKey: publicEncBufferEncoded,
                secretEncKey: secretEncBufferHex,
                phrase: phrase
            };

        case  "eth":
            secretSignBuffer = Buffer.from(keys.secretKey); // 32-bytes private key
            let secretSignKey = `0x${secretSignBuffer.toString('hex')}`;
            let publicSignKey = ethCrypto.publicKeyByPrivateKey(secretSignKey);
            let publicAddress = ethCrypto.publicKey.toAddress(publicSignKey);

            return {
                address: publicAddress,
                publicKey: publicSignKey,
                secretKey: secretSignKey,
                publicEncKey: publicEncBufferEncoded,
                secretEncKey: secretEncBufferHex,
                phrase: phrase
            };

        default:
            log("Current selected network: ", network);
            throw new Error("Can not find selected network");
    }

    async function _session25519(key1, key2) {
        return new Promise(resolve => {
            session25519(key1, key2, (err, result) => resolve(result));
        });
    }
}

async function store(fileObj, userChainId, userChainIdPubKey) {
    log('Browser encrypts to receiver', fileObj, userChainId);

    let fileUploadData = await getFileUploadData(fileObj, userChainId, userChainIdPubKey);
    log('Browser submits encrypted data to API', fileUploadData);

    let submitUrl = getEndpointUrl('data/create');
    log('store post', submitUrl);

    let submitRes = (await axios.post(submitUrl, fileUploadData)).data;
    log('Server returns result', submitRes.data);

    if (submitRes.status === "ERROR") {
        throw new Error(`Error code: ${submitRes.code}, message ${submitRes.message}`);
    } else if (submitRes.action === 'check') {
        if (isNullAny(submitRes.data.name)) {
            throw new Error(`This file has been already registered by another user.`);
        } else {
            throw new Error(`This file already exist as '${submitRes.data.name}'.`);
        }
    }

    return submitRes.data;
}

async function open(dataChainId, userChainId, keyPair) {
    let credentialsResponse = await prepare(dataChainId, userChainId);
    let scanResult = await decrypt(userChainId, dataChainId, keyPair);

    if (isNullAny(scanResult.userId)) {
        throw new Error('Unable to decrypt file');
    }

    //polling server for pass to decrypt message
    return poll(credentialsResponse, keyPair.publicEncKey);
}

async function validate(fileContents, userId, dataId) {
    let requestType = 'verify';
    let trailHash = getHash(dataId + userId + requestType + userId);

    let fileHash = getHash(fileContents);

    let postObj = {
        userId: userId,
        dataId: dataId,
        requestId: requestId,
        requestType: requestType,
        requestBodyHashSignature: 'NULL',
        trailHash: trailHash,
        trailHashSignatureHash: getHash(trailHash),//TODO signature getHash(signMessage(trailHash, keyPair.secretKey))
        encryption: {
            decrDataOrigHash: fileHash
        }
    };

    //TODO signature signMessage(getRequestHash(postObj), keyPair.secretKey)
    postObj.requestBodyHashSignature = getRequestHash(postObj);

    let validateUrl = getEndpointUrl('credentials/validate');

    let result = (await axios.post(validateUrl, postObj)).data;

    return result.data;
}

async function share(dataId, recipientId, keyPair) {
    let getUrl = getEndpointUrl('credentials/share', `&dataId=${dataId}&recipientId=${recipientId}`);
    log('shareencrypted get request', getUrl);

    let getShareResponse = (await axios.get(getUrl)).data;

    if (getShareResponse.data.dataId !== dataId) {
        throw new Error('Unable to create share. Data id mismatch.');
    }

    let userId = keyPair.address;
    recipientId = getShareResponse.data.recipientId;
    dataId = getShareResponse.data.dataId;
    let requestType = 'share';

    let trailHash = getHash(dataId + userId + requestType + recipientId);

    let encryptedPassA = getShareResponse.data.encryption.encryptedPassA;
    let pubKeyA = getShareResponse.data.encryption.pubKeyA;
    let decryptedPassword = decryptDataWithPublicAndPrivateKey(encryptedPassA, pubKeyA, keyPair.secretEncKey);
    let syncPassHash = getHash(decryptedPassword);

    let recipientEncrKey = getShareResponse.data.encryption.recipientEncrKey;
    let reEncryptedPasswordInfo = await encryptDataToPublicKeyWithKeyPair(decryptedPassword, recipientEncrKey, keyPair);

    let createShare = {
        userId: userId,
        dataId: dataId,
        requestId: requestId,
        requestType: requestType,
        requestBodyHashSignature: 'NULL',
        trailHash: trailHash,
        trailHashSignatureHash: getHash(signMessage(trailHash, keyPair.secretKey)),
        recipientId: recipientId,
        encryption: {
            senderEncrKey: keyPair.publicEncKey,
            syncPassHash: syncPassHash,
            encryptedPassA: reEncryptedPasswordInfo.payload
        }
    };

    createShare.requestBodyHashSignature = signMessage(getRequestHash(createShare), keyPair.secretKey);

    let postUrl = getEndpointUrl('share/create');

    let serverPostResponse = (await axios.post(postUrl, createShare)).data;
    log('Share POST to server encryption info', createShare);
    log('Server responds to user device POST', serverPostResponse.data);

    return serverPostResponse.data;
}

async function sign(dataId, recipientId, keyPair, poll = false) {
    let userId = keyPair.address;
    let requestType = 'sign';
    let trailHash = getHash(dataId + userId + requestType + recipientId);

    let userSecretKey = keyPair.secretKey;

    let signObj = {
        dataId: dataId,
        userId: keyPair.address,
        requestId: requestId,
        recipientId: recipientId,
        requestType: requestType,
        requestBodyHashSignature: 'NULL',
        trailHash: trailHash,
        trailHashSignatureHash: getHash(signMessage(trailHash, userSecretKey)),
    };

    signObj.requestBodyHashSignature = signMessage(getRequestHash(signObj, userSecretKey));

    let postUrl = getEndpointUrl('data/sign');
    log('dataSign, ', signObj);

    let serverPostResponse = (await axios.post(postUrl, signObj)).data;
    log('Server responds to data sign POST', serverPostResponse.data);

    if (!poll) {
        return serverPostResponse.data;
    }

    let timeStep = 1000;
    let currentTime = 0;
    let maxTime = 20000;

    while (currentTime < maxTime) {
        await sleep(timeStep);

        let txList = (await verifyHash(dataId, userId)).data;

        if (Array.isArray(txList)) {
            for (let i = 0; i < txList.length; i++) {
                log(txList[i].txStatus);

                if (txList[i].requestType !== 'sign') {
                    continue;
                }

                let currentTxStatus = txList[i].txStatus;
                if (currentTxStatus === 'complete') {
                    return txList[i].txReceipt;
                }

                if (currentTxStatus.includes('error')) {
                    return 'Receipt Unavailable. Transaction processing failed.';
                }
            }
        }

        currentTime += timeStep;
    }

    return false;
}

async function prepare(dataChainId, userChainId) {
    if (isNullAny(browserKeyPair)) {
        browserKeyPair = await newKeyPair(null);
    }
    log('Browser generates keypairB', browserKeyPair);

    let browserPubKeySubmit = {
        dataId: dataChainId,
        userId: userChainId,
        encryption: {
            pubKeyB: browserKeyPair.publicEncKey
        }
    };
    log('submit pubkey payload', browserPubKeySubmit);

    let browserPubKeySubmitUrl = getEndpointUrl('credentials');
    log('browser poll post submit pubKeyB', browserPubKeySubmitUrl);

    let browserPubKeySubmitRes = (await axios.post(browserPubKeySubmitUrl, browserPubKeySubmit)).data;
    log('browser poll post result', browserPubKeySubmitRes.data);

    if (browserPubKeySubmitRes.status === 'ERROR') {
        throw new Error(`Intermediate public key B submission error. Details:${browserPubKeySubmitRes}`);
    }

    return browserPubKeySubmitRes.data;
}

async function decrypt(userId, dataChainId, keyPair) {
    log('Browser renders the dataId as qr code', dataChainId);
    log('User device scans the qr', dataChainId);
    log('User device requests decryption info from server', dataChainId, userId);

    let requestType = 'download';
    let trailHash = getHash(dataChainId + userId + requestType + userId);
    let trailHashSignatureHash = getHash(signMessage(trailHash, keyPair.secretKey));

    let query = `&userId=${userId}&dataId=${dataChainId}&requestId=${requestId}&requestType=${requestType}&requestBodyHashSignature=NULL&trailHash=${trailHash}&trailHashSignatureHash=${trailHashSignatureHash}`;
    let getUrl = getEndpointUrl('credentials/exchange', query);
    getUrl = getUrl.replace('NULL', signMessage(getRequestHash(getUrl), keyPair.secretKey));
    log('decrypt get request', getUrl);

    let serverEncryptionInfo = (await axios.get(getUrl)).data;
    let serverEncryptionData = serverEncryptionInfo.data;
    log('Server responds to device with encryption info', serverEncryptionData);

    let dataEncryption = serverEncryptionData.encryption;
    if (isNullAny(dataEncryption) || isNullAny(dataEncryption.pubKeyB)) {
        throw new Error('Unable to retrieve intermediate public key B.');
    }

    let decryptedPassword = decryptDataWithPublicAndPrivateKey(dataEncryption.encryptedPassA, dataEncryption.pubKeyA, keyPair.secretEncKey);
    log('User device decrypts the sym password', decryptedPassword);

    let syncPassHash = getHash(decryptedPassword);

    let reEncryptedPasswordInfo = await encryptDataToPublicKeyWithKeyPair(decryptedPassword, dataEncryption.pubKeyB, keyPair);
    log('User device reencrypts password for browser', reEncryptedPasswordInfo);

    let devicePost = {
        dataId: dataChainId,
        userId: keyPair.address,
        encryption: {
            syncPassHash: syncPassHash,
            encryptedPassB: reEncryptedPasswordInfo.payload
        }
    };
    log('devicePost', devicePost);

    let postUrl = getEndpointUrl('credentials/exchange');
    log('decrypt post', postUrl);

    let serverPostResponse = (await axios.post(postUrl, devicePost)).data;
    log('User device POST to server encryption info', devicePost);
    log('Server responds to user device POST', serverPostResponse.data);

    return serverPostResponse.data;
}

async function poll(credentialsResponse, receiverPubKey) {
    if (isNullAny(credentialsResponse.userId)) {
        throw new Error(`Server did not return userId. Details:${credentialsResponse}`);
    }

    let pollUrl = getEndpointUrl('data/info', `&userId=${credentialsResponse.userId}&dataId=${credentialsResponse.dataId}`);

    for (let i = 0; i < 50; i++) {
        let pollRes = (await axios.get(pollUrl)).data;

        if (isNullAny(pollRes.data.encryption)) {
            // log('waiting a bit')
            await sleep(1000);
            continue;
        }

        log('Server responds to polling with', pollRes.data);

        let decryptedFile = await processEncryptedFileInfo(pollRes.data, receiverPubKey, browserKeyPair.secretEncKey);

        let validationResult = await validate(decryptedFile.payload, decryptedFile.userId, decryptedFile.dataId);

        if (isNullAny(validationResult)) {
            return validationResult;
        } else {
            return decryptedFile;
        }
    }

    throw new Error('Polling timeout.');


    async function processEncryptedFileInfo(encryptedFileInfo, devicePublicKey, browserPrivateKey) {
        let decryptedSymPassword = decryptDataWithPublicAndPrivateKey(encryptedFileInfo.encryption.encryptedPassB, devicePublicKey, browserPrivateKey);
        log('Browser decrypts sym password', decryptedSymPassword);

        let fullPassword = encodeBase64(keccak256(decryptedSymPassword + encryptedFileInfo.encryption.salt));
        log('Browser composes full password', fullPassword);

        let decryptedFile = decryptDataWithSymmetricKey(encryptedFileInfo.payload, fullPassword);
        log('Browser decrypts the file with the full password', decryptedFile);

        let resultFileInfo = encryptedFileInfo;
        resultFileInfo.payload = decryptedFile;
        delete resultFileInfo.encryption;

        return resultFileInfo;


        function decryptDataWithSymmetricKey(messageWithNonce, key) {
            const keyUint8Array = decodeBase64(key);
            const messageWithNonceAsUint8Array = decodeBase64(messageWithNonce);
            const nonce = messageWithNonceAsUint8Array.slice(0, secretbox.nonceLength);

            const message = messageWithNonceAsUint8Array.slice(
                secretbox.nonceLength,
                messageWithNonce.length
            );

            const decrypted = secretbox.open(message, nonce, keyUint8Array);

            if (isNullAny(decrypted)) {
                throw new Error("Decryption failed");
            }

            return encodeUTF8(decrypted); //base64DecryptedMessage
        }
    }
}

async function select(files, recipients) {
    let validateUrl = getEndpointUrl('selection/create');

    let result = (await axios.post(validateUrl, {
        dataIds: files,
        usersIds: recipients
    })).data;

    if (result.status === 'ERROR') {
        log('Unable to set selection.');
    } else {
        log('Selection set successfully.');
    }

    return result.data.selectionHash;
}

async function getSelected(selectionHash) {
    let getUrl = getEndpointUrl('selection', `&selectionHash=${selectionHash}`);
    log('getSelected get request', getUrl);

    let selectionResponse = (await axios.get(getUrl)).data;

    return selectionResponse.data;
}

async function prepareSelection(selection, keyPair) {
    if (selection.indexOf(':') <= 0) {// check if we have a selection or an id
        throw new Error('Missing selection operation code.');
    }

    let actionSelectionHash = selection.split(':');
    let action = actionSelectionHash[0];
    let selectionHash = actionSelectionHash[1];

    if (action !== 'o') {
        throw new Error('Unsupported selection operation code.');
    }

    let selectionResult = await getSelected(selectionHash);
    log('selection result', selectionResult);

    if (isNullAny(selectionResult.selectionHash)) {
        return [];
    }

    let recipients = selectionResult.usersIds;
    let files = selectionResult.dataIds;
    if (recipients.length !== files.length) {    // the array sizes must be equal
        throw new Error('Invalid selection format.');
    }

    let result = [];
    for (let i = 0; i < files.length; i++) {  // iterate open each entry from the array
        if (keyPair.address !== recipients[i]) {
            log('selection entry omitted', `${recipients[i]}:${files[i]}`);
            continue;                           // skip entries that are not for that keypair
        }

        let credentialsResponse = await prepare(files[i], recipients[i]);

        result.push({dataId: files[i], data: credentialsResponse});
    }

    return result;
}

async function execSelection(selection, keyPair) {
    if (selection.indexOf(':') <= 0) {// check if we have a selection or an id
        throw new Error('Missing selection operation code.');
    }

    let actionSelectionHash = selection.split(':');
    let action = actionSelectionHash[0];
    let selectionHash = actionSelectionHash[1];

    let selectionResult = await getSelected(selectionHash);
    log('selection result', selectionResult);

    if (isNullAny(selectionResult.selectionHash)) {
        return [];
    }

    let recipients = selectionResult.usersIds;
    let files = selectionResult.dataIds;

    if (recipients.length !== files.length) {   // the array sizes must be equal
        throw new Error('Invalid selection format.');
    }

    let result = [];
    for (let i = 0; i < files.length; i++) {  // iterate open each entry from the array
        switch (action) {
            case 'bo':
                if (keyPair.address !== recipients[i]) {
                    log('selection entry omitted', `${recipients[i]}:${files[i]}`);
                    continue;                             // skip entries that are not for that keypair
                }

                if (!isNullAny(keyPair.secretEncKey)) {
                    log('selection entry added', `${recipients[i]}:${files[i]}`);

                    let fileContent = await open(files[i], keyPair.address, keyPair);

                    let fileObj = {
                        dataId: files[i],
                        data: fileContent
                    };

                    result.push(fileObj);
                } else {
                    let credentialsResponse = {
                        dataId: files[i],
                        userId: recipients[i]
                    };

                    let fileContent = await poll(credentialsResponse, keyPair.publicEncKey);

                    let fileObj = {
                        dataId: files[i],
                        data: fileContent//returns empty if error
                    };

                    result.push(fileObj);
                }
                break;

            case 'mo':
                if (keyPair.address !== recipients[i]) {
                    log('selection entry omitted', `${recipients[i]}:${files[i]}`);
                    continue;                      // skip entries that are not for that keypair
                }

                log('selection entry added', `${recipients[i]}:${files[i]}`);

                let scanResult = await decrypt(recipients[i], files[i], keyPair);

                let scanObj = {
                    dataId: files[i],
                    data: scanResult
                };

                result.push(scanObj);
                break;

            case'sh':
                let shareResult = await share(files[i], recipients[i], keyPair);

                let shareObj = {
                    dataId: files[i],
                    data: shareResult
                };

                result.push(shareObj);
                break;

            case'sg':
                let signResult = await sign(files[i], recipients[i], keyPair);

                let signObj = {
                    dataId: files[i],
                    data: signResult
                };

                result.push(signObj);
                break;

            default :
                throw new Error('Unsupported selection operation code.');
        }
    }

    return result;
}

function signMessage(message, secretKey) {
    try {
        switch (network) {
            case "ae":
                let signatureBytes = naclSign(Buffer.from(message), hexStringToByte(secretKey));

                return encodeBase58Check(signatureBytes);// signatureB58;

            case "eth":
                const messageHash = ethCrypto.hash.keccak256(message);

                return ethCrypto.sign(
                    secretKey,
                    messageHash
                );// signature;
        }
    } catch (ignored) {
        return false;
    }


    function naclSign(data, privateKey) {
        return nacl.sign.detached(Buffer.from(data), Buffer.from(privateKey));
    }
}

function verifyMessage(message, signature, pubKey) {
    try {
        if (isNullAny(pubKey)) {
            return false;
        }

        switch (network) {
            case "ae":
                let verifyResult = nacl.sign.detached.verify(
                    new Uint8Array(Buffer.from(message)),
                    decodeBase58Check(signature),
                    decodeBase58Check(pubKey.split('_')[1])
                );

                if (isNullAny(verifyResult)) {
                    return false;
                }

                return pubKey;

            case "eth":
                return ethCrypto.recover(
                    signature,
                    ethCrypto.hash.keccak256(message)
                ); //signer;
        }
    } catch (ignored) {
        return false;
    }
}

async function registerHash(dataChainId, requestType, targetUserId, keyPair, poll = false) {
    let trailHash = getHash(dataChainId + keyPair.address + requestType + targetUserId);

    let requestId = trailHash;

    let body = {
        dataId: dataChainId,
        userId: keyPair.address,
        requestId: trailHash,
        recipientId: targetUserId,
        requestType: requestType,
        requestBodyHashSignature: trailHash,
        trailHash: trailHash,
        trailHashSignatureHash: getHash(signMessage(trailHash, keyPair.secretKey)),
    };

    let postUrl = getEndpointUrl('tx/create');
    log('registerHash, ', body);

    let serverPostResponse = (await axios.post(postUrl, body)).data;
    log('Server responds to registerHash POST', serverPostResponse.data);

    if (!poll) {
        return serverPostResponse.data;
    }

    let timeStep = 1000;
    let currentTime = 0;
    let maxTime = 20000;

    while (currentTime < maxTime) {
        await sleep(timeStep);

        let txList = (await verifyHash(dataChainId, keyPair.address)).data;

        if (Array.isArray(txList)) {
            for (let i = 0; i < txList.length; i++) {
                log(txList[i].txStatus);

                if (txList[i].requestId !== requestId) {
                    continue;
                }

                if (txList[i].txStatus === 'complete') {
                    return txList[i].txReceipt;
                }

                if (txList[i].txStatus.includes('error')) {
                    return 'Receipt Unavailable. Transaction processing failed.';
                }
            }
        }

        currentTime += timeStep;
    }

    return false;
}

async function verifyHash(dataChainId, userId, requestId) {
    let query = `&userId=${userId}&dataId=${dataChainId}`;

    if (!isNullAny(requestId)) {
        query += `&requestId=${requestId}`;
    }

    let getUrl = getEndpointUrl('tx/check', query);
    log('query URL', getUrl);

    let serverResponse = (await axios.get(getUrl)).data;
    log('Server responds to verifyHash GET', serverResponse.data);

    return serverResponse.data;
}


module.exports = {

    debug: setDebugMode,
    /* Specify API token and API host */

    init: init,

    // login i login with challenge
    // login hammer 0(account) 0x.. (challenge code)
    // node hammer login 1 (second user's login)
    login: login,
    loginWithChallenge: loginWithChallenge,

    /* Create a keypair and recovery phrase */
    newKeyPair: newKeyPair,

    /* Encrypt, upload and register a file or any data */
    //upload new file
    store: store,
    /* Retrieve fle - used in case of client interaction */
    // node hammer open 0x...(dataId) 0 (this account, different number = different account)
    // node hammer open 0x..(dataId) 1 (user's credentials) 1 (user's credentials API)
    // hammer -i <acc.json> store <filename.txt>
    // hammer -i <acc.json> share <fileID> <recipientID>
    // hammer -i <acc.json> open <fileID>
    open: open,
    // verify file contents against a hash and its owner/recipient
    validate: validate,
    // node hammer share 0x..(dataId) 1(user sender) 0(user receiver)
    share: share,
    sign: sign,

    /* Retrieve file - used in case of browser interaction */
    // submit credentials of the decrypting browser
    prepare: prepare,
    // decrypt password and re-encrypt for decrypting browser
    decrypt: decrypt,
    // polling on the side of decrypting browser for encrypted file
    poll: poll,

    // node hammer select-share 0x...(fileID) 2k_...(recipient) 0(sender) returns "s:qrCode"
    select: select,
    selection: getSelected,
    prepareSelection: prepareSelection,
    // node hammer exec o:0x...(selection hash)
    execSelection: execSelection,

    signMessage: signMessage,
    verifyMessage: verifyMessage,

    registerHash: registerHash,
    verifyHash: verifyHash
};
