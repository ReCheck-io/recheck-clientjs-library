const {box, secretbox, randomBytes} = require('tweetnacl');
const {decodeUTF8, encodeUTF8, encodeBase64, decodeBase64} = require('tweetnacl-util');
const diceware = require('diceware');
const session25519 = require('session25519');
const {keccak256, keccak_256} = require('js-sha3');
const keccak256Old = require('keccak256');
const bs58check = require('bs58check');
const axios = require('axios');
const nacl = require('tweetnacl');
const ethCrypto = require('eth-crypto');
const stringify = require('json-stable-stringify');
const wordList = require('./wordlist');


let debug = false;

let baseUrl = 'http://localhost:4000';
let token = null;
let network = "ae"; //ae,eth

let defaultRequestId = 'ReCheck';
const pollingTime = 90;
let isWorkingExecReEncr = false;
let mapShouldBeWorkingPollingForFunctionId = [];

let browserKeyPair = undefined; // represents the browser temporary keypair while polling
let recipientsEmailLinkKeyPair = null;
let notificationObject = null;


const newNonce = () => randomBytes(box.nonceLength);

const generateKey = () => encodeBase64(randomBytes(secretbox.keyLength));

const log = (message, params) => {
    if (debug) {
        console.log(`[${message}]`, params ? params : '');
    }
};

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

async function processExternalId(dataIdInput, userId, isExternal) {
    if (!isExternal) {
        return dataIdInput;
    }

    let isArray = Array.isArray(dataIdInput);
    if (!isArray) {
        dataIdInput = [dataIdInput];
    }

    for (let i = 0; i < dataIdInput.length; i++) {
        dataIdInput[i] = await convertExternalId(dataIdInput[i], userId);
    }

    if (isArray) {
        return dataIdInput;
    } else {
        return dataIdInput[0];
    }
}

async function processTxPolling(dataId, userId, matchTxPropName, matchTxPropValue) {

    let timeStep = 1000;
    let currentTime = 0;
    let maxTime = 20000;

    while (currentTime < maxTime) {
        await sleep(timeStep);

        let txList = await checkHash(dataId, userId);

        if (Array.isArray(txList)) {
            for (let i = 0; i < txList.length; i++) {
                log(txList[i].txStatus);

                if (txList[i][matchTxPropName] !== matchTxPropValue) {
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

function isValidEmail(emailAddress) {
    return /(.+)@(.+){2,}\.(.+){2,}/.test(emailAddress);
}

function isValidAddress(address) {
    switch (network) {
        case'eth':
            return new RegExp(`^0x[0-9a-fA-F]{40}$`).test(address);
        case'ae':
            return new RegExp(`^re_[0-9a-zA-Z]{41,}$`).test(address);
        default:
            return false;
    }
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

    function encryptData(secretOrSharedKey, message, key) {
        if (typeof message !== "string") {
            throw new Error("only string allowed for message for encryption");
        }

        const nonce = newNonce();
        const messageUint8 = decodeUTF8(message);

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

        return encodeUTF8(decrypted);//base64DecryptedMessage
    }
}

async function processEncryptedFileInfo(encryptedFileInfo, devicePublicKey, browserPrivateKey) {
    let decryptedSymPassword = decryptDataWithPublicAndPrivateKey(encryptedFileInfo.encryption.encryptedPassB, devicePublicKey, browserPrivateKey);
    log('Browser decrypts sym password', decryptedSymPassword);

    let fullPassword = encodeBase64(hexStringToByte(keccak256(decryptedSymPassword + encryptedFileInfo.encryption.salt)));
    log('Browser composes full password', fullPassword);

    let decryptedFile = decryptDataWithSymmetricKey(encryptedFileInfo.payload, fullPassword);
    log('Browser decrypts the file with the full password', decryptedFile);

    let resultFileInfo = encryptedFileInfo;
    resultFileInfo.payload = decryptedFile;
    delete resultFileInfo.encryption;

    return resultFileInfo;


    function decryptDataWithSymmetricKey(messageWithNonce, key) {
        const keyUint8Array = decodeBase64(key);

        const messageWithNonceAsUint8Array = new Uint8Array(Array.prototype.slice.call(new Buffer(messageWithNonce, 'base64'), 0));//decodeBase64 without validation

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

function getHash(string) {
    return `0x${keccak256(string)}`;
}

function getHashOld(string) {
    return `0x${keccak256Old(string).toString('hex')}`;
}

function getHashFromHashObject(hashObj) {
    return `0x${hashObj.hex()}`;
}

function getUpdatedHashObj(string, hashObj = null) {
    if (isNullAny(hashObj)) {
        hashObj = keccak_256.create();
    }

    return hashObj.update(string);
}

function getRequestHash(requestBodyOrUrl) {
    let requestString = '';

    if (typeof requestBodyOrUrl === "object") {
        let resultObj = JSON.parse(JSON.stringify(requestBodyOrUrl));
        resultObj.payload = '';
        resultObj.requestBodyHashSignature = 'NULL';

        requestString = stringify(resultObj).replace(/\s/g, "");
    } else {
        requestString = requestBodyOrUrl.replace(/([&|?]requestBodyHashSignature=)(.*?)([&]|$)/g, '$1NULL$3');
        requestString = getUrlPathname(requestString);
    }

    return getHash(requestString);

    function getUrlPathname(url) {
        let urlSplit = url.split('/');

        if (urlSplit.length < 4) {
            throw new Error(`Can not get url pathname from ${url}`);
        }

        if (urlSplit[3] === "chain") {
            url = url.replace("/chain", "");
        }

        let host = `${urlSplit[0]}//${urlSplit[2]}`;

        return url.replace(host, '');
    }
}

function getTrailHash(dataChainId, senderChainId, requestType, recipientChainId = senderChainId, trailExtraArgs = null) {
    if (isNullAny(trailExtraArgs)) {
        trailExtraArgs = "";
    } else {
        trailExtraArgs = JSON.stringify(trailExtraArgs);
    }

    return getHash(dataChainId + senderChainId + requestType + recipientChainId + trailExtraArgs);
}

function isNullAny(...args) {
    for (let i = 0; i < args.length; i++) {
        let current = args[i];
        if ((current && (current.constructor === Object || current.constructor === keccak_256.create().constructor))) {
            try {
                current = JSON.parse(JSON.stringify(args[i]));
            } catch (ignored) {
            }
        }

        if (current == null || // element == null covers element === undefined
            (current.hasOwnProperty("length") && current.length === 0) || // has length and it's zero
            (current.constructor === Object && Object.keys(current).length === 0) || // is an Object and has no keys
            current.toString().toLowerCase() === "null" ||
            current.toString().toLowerCase() === "undefined" ||
            current.toString().trim() === "") {
            return true;
        }

        if (typeof current !== "number") {
            try {
                if (+new Date(current) === 0) {
                    // is not a number and can be parsed as null date 1970
                    return true;
                }
            } catch (ignored) {
            }
        }

        try {
            const parsed = JSON.parse(current);
            if (parsed !== current && isNullAny(parsed)) {
                // recursive check for stringified object
                return true;
            }
        } catch (ignored) {
        }

        // check for hashes of null values
        if ([
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", // null/undefined/""/[].toString(),
            "0x7bc087f4ef9d0dc15fef823bff9c78cc5cca8be0a85234afcfd807f412f40877", // {}.toString()
            "0x518674ab2b227e5f11e9084f615d57663cde47bce1ba168b4c19c7ee22a73d70", // JSON.stringify([])
            "0xb48d38f93eaa084033fc5970bf96e559c33c4cdc07d889ab00b4d63f9590739d", // JSON.stringify({})
            "0xefbde2c3aee204a69b7696d4b10ff31137fe78e3946306284f806e2dfc68b805", // "null"
            "0x019726c6babc1de231f26fd6cbb2df2c912784a2e1ba55295496269a6d3ff651", // "undefined"
            "0x681afa780d17da29203322b473d3f210a7d621259a4e6ce9e403f5a266ff719a", // " "
            "0xfc6664300e2ce056cb146b05edef3501ff8bd027c49a8dde866901679a24fb7e", // new Date(0).toString()
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        ].includes(current)) {
            return true;
        }
    }

    return false;
}

const setDebugMode = (debugFlag) => {
    debug = debugFlag;
};

const setDefaultRequestId = (requestId) => {
    if (!isNullAny(requestId)) {
        defaultRequestId = requestId;
    }
}

function init(sourceBaseUrl, sourceNetwork = network, sourceToken = token) {
    baseUrl = sourceBaseUrl;

    if (!isNullAny(sourceToken)) {
        token = sourceToken;
    }

    if (!isNullAny(sourceNetwork)) {
        network = sourceNetwork;
    }
}

async function getServerInfo() {
    let getUrl = getEndpointUrl('login/check');

    let serverResponse = (await axios.get(getUrl)).data;

    if (isNullAny(serverResponse)) {
        throw new Error('Unable to connect to server.');
    }

    return {
        apiVersion: serverResponse.apiVersion,
        blockchain: serverResponse.blockchain,
        contractAddress: serverResponse.contractAddress
    };
}

async function getLoginChallenge(returnObj = {}) {
    let appendix = '';
    if (!isNullAny(returnObj)) {
        appendix = `&returnChallenge=${returnObj.returnChallenge}&returnUrl=${returnObj.returnUrl}`;
    }

    let getChallengeUrl = getEndpointUrl('login/challenge', appendix);

    let challengeResponse = (await axios.get(getChallengeUrl)).data;

    if (isNullAny(challengeResponse.data.challenge)) {
        throw new Error('Unable to retrieve login challenge.');
    }

    return challengeResponse.data.challenge;
}

async function login(keyPair, firebaseToken = 'notoken', loginDevice = 'unknown', returnObj = {}) {
    let loginChallenge = await getLoginChallenge(returnObj);

    return await loginWithChallenge(
        loginChallenge, keyPair, firebaseToken, loginDevice
    );
}

async function loginWithChallenge(challenge, keyPair, firebaseToken = 'notoken', loginDevice = 'unknown') {
    let payload = {
        action: 'login',
        pubKey: keyPair.publicKey,
        pubEncKey: keyPair.publicEncKey,
        firebase: firebaseToken,
        challenge: challenge,
        challengeSignature: signMessage(challenge, keyPair.secretKey),//signatureB58
        rtnToken: 'notoken',
        loginDevice: loginDevice,
    };

    let loginUrl = getEndpointUrl('login/mobile');

    let loginPostResult = (await axios.post(loginUrl, payload)).data;

    if (loginPostResult.status === 'ERROR') {
        throw loginPostResult.data;
    }

    let resultObj = loginPostResult.data;
    if (isNullAny(resultObj) || isNullAny(resultObj.rtnToken)) {
        throw new Error('Unable to retrieve API token.');
    }

    token = resultObj.rtnToken;

    if (!isNullAny(resultObj.returnChallenge, resultObj.returnUrl)
        && resultObj.returnUrlSendStatus !== "success") {
        throw resultObj.returnUrlSendStatus;
    }

    return token;
}

async function newKeyPair(passPhrase) {

    if (isNullAny(passPhrase)) {
        passPhrase = diceware(12);
    } else {
        passPhrase = passPhrase.toLowerCase();
        const words = passPhrase.split(' ');

        if (words.length !== 12) {
            throw ('Invalid passphrase. Must be 12 words long.');
        }

        for (let i = 0; i < 12; i++) {
            if (!wordList.includes(words[i])) {
                throw("An existing word is not from the dictionary, your secret phrase is wrong.")
            }
        }
    }

    let keys = await _session25519(passPhrase, getHash(passPhrase));

    let publicEncBufferEncoded = encodeBase58Check(Buffer.from(keys.publicKey));
    let secretEncBufferHex = Buffer.from(keys.secretKey).toString('hex');  // 32-bytes private key
    let secretSignBuffer;
    switch (network) {
        case "ae":
            let publicSignBuffer = Buffer.from(keys.publicSignKey);
            secretSignBuffer = Buffer.from(keys.secretSignKey).toString('hex'); // 64-bytes private key
            let address = `re_${encodeBase58Check(publicSignBuffer)}`;

            return {
                address: address,
                publicKey: address,
                secretKey: secretSignBuffer,
                publicEncKey: publicEncBufferEncoded,
                secretEncKey: secretEncBufferHex,
                phrase: passPhrase
            };

        case "eth":
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
                phrase: passPhrase
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

async function store(fileObj, userChainId, userChainIdPubEncKey, externalId = null, txPolling = false, trailExtraArgs = null) {

    log('Browser encrypts to receiver', fileObj, userChainId);

    let fileUploadData = await getFileUploadData(fileObj, userChainId, userChainIdPubEncKey, trailExtraArgs);
    log('Browser submits encrypted data to API', fileUploadData);

    if (!isNullAny(externalId)) {
        await saveExternalId(externalId, userChainId, fileUploadData.encryption.dataOriginalHash);
    }

    let submitUrl = getEndpointUrl('data/create');
    log('store post', submitUrl);

    let submitRes = (await axios.post(submitUrl, fileUploadData)).data;
    log('Server returns result', submitRes.data);

    if (submitRes.status === "ERROR") {
        throw submitRes.data;
    }

    if (!txPolling) {
        return submitRes.data;
    }

    return await processTxPolling(getHash(fileObj.payload), userChainId, 'requestType', 'upload');

    async function getFileUploadData(fileObj, userChainId, userChainIdPubEncKey, trailExtraArgs = null) {
        let fileContents = fileObj.payload;
        let encryptedFile = await encryptFileToPublicKey(fileContents, userChainIdPubEncKey);
        let syncPassHash = getHash(encryptedFile.credentials.syncPass);
        let dataOriginalHash = getHash(fileContents);
        let dataChainId = getHash(dataOriginalHash);
        let requestType = 'upload';

        let trailHash = getTrailHash(dataChainId, userChainId, requestType, userChainId, trailExtraArgs);

        let fileUploadData = {
            userId: userChainId,
            dataId: dataChainId,
            requestId: defaultRequestId,
            requestType: requestType,
            requestBodyHashSignature: 'NULL',
            trailHash: trailHash,
            trailHashSignatureHash: getHash(trailHash),//TODO signature getHash(signMessage(trailHash, keyPair.secretKey))
            dataName: fileObj.dataName,
            dataExtension: fileObj.dataExtension,
            category: fileObj.category,
            keywords: fileObj.keywords,
            dataFolderId: fileObj.dataFolderId,
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


        async function encryptFileToPublicKey(fileData, dstPublicEncKey) {
            let fileKey = generateKey();
            let saltKey = generateKey();
            log('fileKey', fileKey);
            log('saltKey', saltKey);

            let symKey = encodeBase64(hexStringToByte(keccak256(fileKey + saltKey)));
            log('symKey', symKey);
            log('fileData', fileData);

            let encryptedFile = encryptDataWithSymmetricKey(fileData, symKey);
            let encryptedPass = await encryptDataToPublicKeyWithKeyPair(fileKey, dstPublicEncKey);

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
}

async function storeLargeFiles(fileObj, userChainId, userChainIdPubEncKey, progressCb = null, trailExtraArgs = null) {
    if (isNullAny(fileObj) || isNullAny(fileObj.file) || isNullAny(userChainId) || isNullAny(userChainIdPubEncKey)) {
        throw Error('Missing file object and/or file content!');
    }

    let file = fileObj.file;
    let fileSizeBytes = file.size;
    
    let offset = 0;
    let chunkId = 0;
    let dataId = null;
    let dataOriginalHash = null;
    let dataHash = null;
    let chunkHash = null;
    let fileUploadData = null;

    let chunkSizeBytes = fileObj.maxChunkSizeKB * 1024;
    let chunksCount = Math.ceil(fileSizeBytes / chunkSizeBytes);

    chunksCount = chunksCount < 2 ? 2 : chunksCount;
    chunkSizeBytes = Math.ceil(fileSizeBytes / chunksCount);

    let reader = new FileReader();
    let response = null;

    await uploadFile();

    return response;

    async function uploadFile(shouldGetOnlyHash = true) {
        let nextSliceEnd = offset + chunkSizeBytes;
        nextSliceEnd = nextSliceEnd > fileSizeBytes ? fileSizeBytes : nextSliceEnd;
        let chunkData = file.slice(offset, nextSliceEnd);

        reader.readAsBinaryString(chunkData);

        return new Promise(function (resolve, reject) {
            reader.onloadend = async function (event) {
                if (event.target.readyState !== FileReader.DONE) reject();

                offset += chunkSizeBytes;
                if (progressCb) progressCb(event.target.result.length);
                let chunkData = btoa(event.target.result);

                if (shouldGetOnlyHash) {
                    if (offset < file.size) {
                        dataHash = getUpdatedHashObj(chunkData, dataHash);
                        return resolve(uploadFile());
                    } else {
                        dataOriginalHash = RECHECK.getHashFromHashObject(dataHash),
                        dataId = getHash(dataOriginalHash),
                        dataHash = 0;
                        offset = 0;
                        return resolve(uploadFile(false));
                    }
                } else {
                    chunkId++;
                    chunkHash = getHash(chunkData);
                    
                    let chunkObj = {
                        dataOriginalHash,
                        dataId,
                        chunkId,
                        chunkHash,
                        chunksCount,
                        payload: chunkData,
                    }

                    fileUploadData = await getFileUploadData(
                        { ...fileObj, ...chunkObj }, userChainId, userChainIdPubEncKey, trailExtraArgs
                    );

                    const dataContentPostUrl = getEndpointUrl('data/content');
                    let result = (await axios.post(dataContentPostUrl, fileUploadData)).data;

                    if (!result 
                        || result.status !== "OK" 
                        || !result.data 
                        || result.data.dataId !== chunkObj.dataId 
                        || result.data.chunkId !== chunkObj.chunkId) {
                            throw Error("Chunk upload fail!");
                    }

                    // On success
                    if (offset < fileSizeBytes) {
                        return resolve(uploadFile(false));
                    } else {
                        // TODO: /data/create -> all as store w/o payload
                        const dataCreatePostUrl = getEndpointUrl('data/create');
                        delete fileUploadData.payload;
                        let result = await axios.post(dataCreatePostUrl, { ...fileUploadData });
                        console.log('Completed!', "dataId hash", result);
                        response = { status: 'success' };
                        resolve();
                    }
                }
            };
        });
        
    }

    async function getFileUploadData(fileObj, userChainId, userChainIdPubEncKey, trailExtraArgs = null) {
        let fileContents = fileObj.payload;
        let encryptedFile = await encryptFileToPublicKey(fileContents, userChainIdPubEncKey);
        let syncPassHash = getHash(encryptedFile.credentials.syncPass);
        // let dataOriginalHash = getHash(fileContents);
        // let dataChainId = getHash(dataOriginalHash);
        let requestType = 'upload';

        let trailHash = getTrailHash(fileObj.dataId, userChainId, requestType, userChainId, trailExtraArgs);

        let fileUploadData = {
            chunkId: fileObj.chunkId,
            chunkHash: fileObj.chunkHash,
            chunksCount: fileObj.chunksCount,
            userId: userChainId,
            dataId: fileObj.dataId,
            requestId: defaultRequestId,
            requestType: requestType,
            requestBodyHashSignature: 'NULL',
            trailHash: trailHash,
            trailHashSignatureHash: getHash(trailHash),//TODO signature getHash(signMessage(trailHash, keyPair.secretKey))
            dataName: fileObj.dataName,
            dataExtension: fileObj.dataExtension,
            category: fileObj.category,
            keywords: fileObj.keywords,
            dataFolderId: fileObj.dataFolderId,
            payload: encryptedFile.payload,
            encryption: {
                dataOriginalHash: fileObj.dataOriginalHash,
                salt: encryptedFile.credentials.salt,
                passHash: syncPassHash,
                encryptedPassA: encryptedFile.credentials.encryptedPass,
                pubKeyA: encryptedFile.credentials.encryptingPubKey
            }
        };

        // TODO: signature signMessage(getRequestHash(fileUploadData), keyPair.secretKey)
        fileUploadData.requestBodyHashSignature = getRequestHash(fileUploadData);

        return fileUploadData;


        async function encryptFileToPublicKey(fileData, dstPublicEncKey) {
            let fileKey = generateKey();
            let saltKey = generateKey();
            log('fileKey', fileKey);
            log('saltKey', saltKey);

            let symKey = encodeBase64(hexStringToByte(keccak256(fileKey + saltKey)));
            log('symKey', symKey);
            log('fileData', fileData);

            let encryptedFile = encryptDataWithSymmetricKey(fileData, symKey);
            let encryptedPass = await encryptDataToPublicKeyWithKeyPair(fileKey, dstPublicEncKey);

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
}

async function storeData(files, userChainId, userChainIdPubEncKey, progressCb = null, ...props) {
    if (isNullAny(files)) {
        throw Error("Missing files!");
    }

    files = Array.isArray(files) ? files : [files];

    let totalFileSizeBytes = files.reduce((acc, cur) => acc + cur.file.size, 0);
    let totalBytesRead = 0;
    let results = [];

    for (let i = 0; i < files.length; i++) {
        const currentFile = files[i];

        storeLargeFiles(currentFile, userChainId, userChainIdPubEncKey, totalProgressCb, ...props)
            .then((response) => {
                results[i] = response;
            })
            .catch((err) => {
                console.log('file read error', err);
                results[i] = err;
            });
    }

    return (async function returnIfReady() {
        if (results.length === files.length) {
            return results
        }

        await sleep(100);
        return returnIfReady();
    })();

    function totalProgressCb(bytesRead) {
        totalBytesRead += bytesRead;
        
        progressCb(Math.floor(((totalBytesRead / totalFileSizeBytes) * 100) / 2));
    }
}

async function open(dataChainId, userChainId, keyPair, isExternal = false, txPolling = false, trailExtraArgs = null) {

    dataChainId = await processExternalId(dataChainId, userChainId, isExternal);

    let credentialsResponse = await prepare(dataChainId, userChainId);
    let scanResult = await reEncrypt(userChainId, dataChainId, keyPair, trailExtraArgs);

    if (isNullAny(scanResult.userId)) {
        throw new Error('Unable to decrypt file');
    }

    //polling server for pass to decrypt message
    let credentialsResult = await pollOpen(credentialsResponse);

    await pollChunks(dataChainId, userChainId, keyPair.publicEncKey);

    // Validate payload
    // let validationResult = await validate(decryptedFile.payload, decryptedFile.userId, decryptedFile.dataId, txPolling, trailExtraArgs);
}

async function validate(fileContents, userId, dataId, isExternal = false, txPolling = false, trailExtraArgs = null) {

    dataId = await processExternalId(dataId, userId, isExternal);

    let requestType = 'verify';

    let trailHash = getTrailHash(dataId, userId, requestType, userId, trailExtraArgs);

    let fileHash = getHash(fileContents);

    let postObj = {
        userId: userId,
        dataId: dataId,
        requestId: defaultRequestId,
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

    if (!txPolling) {
        return result.data;
    }

    return await processTxPolling(dataId, userId, 'requestType', 'verify');
}

async function share(dataId, recipient, keyPair, isExternal = false, txPolling = false, trailExtraArgs = null, emailSharePubKeys = null, execFileSelectionHash = null) {

    let userId = keyPair.address;

    dataId = await processExternalId(dataId, userId, isExternal);

    let recipientType;
    let isEmailShare = false;
    if (!isValidEmail(recipient)) {
        if (!isValidAddress(recipient)) {
            throw new Error(`Invalid recipient email/id format: ${recipient}`);
        }

        recipientType = 'recipientId';
    } else {
        recipientType = 'recipientEmail';
        isEmailShare = true;
    }

    let getUrl = getEndpointUrl('share/credentials', `&dataId=${dataId}&${recipientType}=${recipient}`);
    log('shareencrypted get request', getUrl);

    let getShareResponse = (await axios.get(getUrl)).data;

    if (getShareResponse.status === "ERROR") {
        throw getShareResponse.data;
    }

    if (getShareResponse.data.dataId !== dataId) {
        throw new Error('Unable to create share. Data id mismatch.');
    }

    recipient = getShareResponse.data[recipientType];
    dataId = getShareResponse.data.dataId;

    let requestType = isEmailShare ? 'email' : 'share';

    let trailHash = getTrailHash(dataId, userId, requestType, recipient, trailExtraArgs);

    let encryptedPassA = getShareResponse.data.encryption.encryptedPassA;
    let pubKeyA = getShareResponse.data.encryption.pubKeyA;
    let decryptedPassword = decryptDataWithPublicAndPrivateKey(encryptedPassA, pubKeyA, keyPair.secretEncKey);
    let syncPassHash = getHash(decryptedPassword);

    let recipientEncrKey = getShareResponse.data.encryption.recipientEncrKey;

    let recipientEmailLinkKeyPair;
    if (isEmailShare) {
        if (isNullAny(emailSharePubKeys)) {
            recipientEmailLinkKeyPair = await newKeyPair(null);
        } else {
            recipientEmailLinkKeyPair = recipientsEmailLinkKeyPair;
        }

        recipientEncrKey = recipientEmailLinkKeyPair.publicEncKey;
    }

    let reEncryptedPasswordInfo = await encryptDataToPublicKeyWithKeyPair(decryptedPassword, recipientEncrKey, keyPair);

    let createShare = {
        userId: userId,
        dataId: dataId,
        requestId: defaultRequestId,
        requestType: requestType,
        requestBodyHashSignature: 'NULL',
        trailHash: trailHash,
        trailHashSignatureHash: getHash(signMessage(trailHash, keyPair.secretKey)),
        encryption: {
            senderEncrKey: keyPair.publicEncKey,
            syncPassHash: syncPassHash,
            encryptedPassA: reEncryptedPasswordInfo.payload
        }
    };
    createShare[recipientType] = recipient;

    createShare.requestBodyHashSignature = signMessage(getRequestHash(createShare), keyPair.secretKey);

    let postUrl = getEndpointUrl('share/create');

    let serverPostResponse = (await axios.post(postUrl, createShare)).data;
    log('Share POST to server encryption info', createShare);
    log('Server responds to user device POST', serverPostResponse.data);

    let result = serverPostResponse.data;
    if (serverPostResponse.status === "ERROR") {
        throw result;
    }

    let shareUrl = await generateEmailShareUrl();

    if (!txPolling) {
        return result;
    }

    result = await processTxPolling(dataId, userId, 'requestType', requestType);
    if (isEmailShare) {
        result.data = result;
        result.shareUrl = shareUrl;
    }

    return result;


    async function generateEmailShareUrl() {
        let generatedShareUrl = null;
        if (!isEmailShare) {
            return generatedShareUrl;
        }

        if (isNullAny(result.selectionHash)) {
            throw new Error('Unable to create email share selection hash. Contact your service provider.');
        }

        let selectionHash = result.selectionHash;

        if (!isNullAny(execFileSelectionHash)) {
            selectionHash = execFileSelectionHash;
        }

        generatedShareUrl = `${baseUrl}/view/email/${selectionHash}`;

        let queryObj = {
            selectionHash: selectionHash,
            pubKey: recipientEmailLinkKeyPair.publicKey,
            pubEncKey: recipientEncrKey,
            shareUrl: generatedShareUrl,
            requestBodyHashSignature: 'NULL',
        }
        queryObj.requestBodyHashSignature = signMessage(getRequestHash(queryObj), keyPair.secretKey);

        let query = Buffer.from(stringify(queryObj)).toString('base64');

        let fragmentObj = {
            secretKey: recipientEmailLinkKeyPair.secretKey,
            secretEncKey: recipientEmailLinkKeyPair.secretEncKey,
        }

        let fragment = Buffer.from(stringify(fragmentObj)).toString('base64');
        generatedShareUrl = `${generatedShareUrl}?q=${query}#${fragment}`;
        result.shareUrl = generatedShareUrl;

        if (!isNullAny(execFileSelectionHash, emailSharePubKeys)) {

            let encryptedShareUrl = await encryptDataToPublicKeyWithKeyPair(generatedShareUrl, emailSharePubKeys.pubEncKey, keyPair);
            let emailSelectionsObj = {
                selectionHash: selectionHash,
                pubKey: emailSharePubKeys.pubKey,
                pubEncKey: emailSharePubKeys.pubEncKey,
                encryptedUrl: encryptedShareUrl.payload,
            };

            let submitUrl = getEndpointUrl('email/share/create');
            let submitRes = (await axios.post(submitUrl, emailSelectionsObj)).data;
            log('Server returns result', submitRes.data);
            if (submitRes.status === "ERROR") {
                throw submitRes.data;
            }
        }

        return generatedShareUrl;
    }
}

async function sign(dataId, recipientId, keyPair, isExternal = false, txPolling = false, trailExtraArgs = null) {
    let userId = keyPair.address;

    dataId = await processExternalId(dataId, userId, isExternal);

    let requestType = 'sign';

    let trailHash = getTrailHash(dataId, userId, requestType, recipientId, trailExtraArgs);

    let userSecretKey = keyPair.secretKey;

    let signObj = {
        dataId: dataId,
        userId: keyPair.address,
        requestId: defaultRequestId,
        recipientId: recipientId,
        requestType: requestType,
        requestBodyHashSignature: 'NULL',
        trailHash: trailHash,
        trailHashSignatureHash: getHash(signMessage(trailHash, userSecretKey)),
    };

    signObj.requestBodyHashSignature = signMessage(getRequestHash(signObj), userSecretKey);

    let postUrl = getEndpointUrl('signature/create');
    log('dataSign, ', signObj);

    let serverPostResponse = (await axios.post(postUrl, signObj)).data;
    log('Server responds to data sign POST', serverPostResponse.data);

    if (!txPolling) {
        return serverPostResponse.data;
    }

    return await processTxPolling(dataId, userId, 'requestType', 'sign');
}

async function prepare(dataChainId, userChainId, isExternal = false) {

    dataChainId = await processExternalId(dataChainId, userChainId, isExternal);

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

    let browserPubKeySubmitUrl = getEndpointUrl('credentials/create/pubkeyb');
    log('browser poll post submit pubKeyB', browserPubKeySubmitUrl);

    let browserPubKeySubmitRes = (await axios.post(browserPubKeySubmitUrl, browserPubKeySubmit)).data;
    log('browser poll post result', browserPubKeySubmitRes.data);

    if (browserPubKeySubmitRes.status === 'ERROR') {
        throw browserPubKeySubmitRes.data;
    }

    return browserPubKeySubmitRes.data;
}

async function reEncrypt(userId, dataChainId, keyPair, isExternal = false, trailExtraArgs = null) {

    dataChainId = await processExternalId(dataChainId, userId, isExternal);

    log('Browser renders the dataId as qr code', dataChainId);
    log('User device scans the qr', dataChainId);
    log('User device requests decryption info from server', dataChainId, userId);

    let requestType = 'download';
    let trailHash = getTrailHash(dataChainId, userId, requestType, userId, trailExtraArgs);

    let trailHashSignatureHash = getHash(signMessage(trailHash, keyPair.secretKey));

    let query = `&userId=${userId}&dataId=${dataChainId}&requestId=${defaultRequestId}&requestType=${requestType}&requestBodyHashSignature=NULL&trailHash=${trailHash}&trailHashSignatureHash=${trailHashSignatureHash}`;
    let getUrl = getEndpointUrl('credentials/info', query);
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

    let postUrl = getEndpointUrl('credentials/create/passb');
    log('decrypt post', postUrl);

    let serverPostResponse = (await axios.post(postUrl, devicePost)).data;
    log('User device POST to server encryption info', devicePost);
    log('Server responds to user device POST', serverPostResponse.data);

    return serverPostResponse.data;
}

async function pollOpen(credentialsResponse, isExternal = false) {
    let userId = credentialsResponse.userId;
    let dataId = credentialsResponse.dataId;

    if (isNullAny(userId, dataId)) {
        throw new Error(`Server did not return userId or dataId/externalId. Details:${credentialsResponse}`);
    }

    dataId = await processExternalId(dataId, userId, isExternal);

    let pollUrl = getEndpointUrl('data/info', `&userId=${userId}&dataId=${dataId}`);

    for (let i = 0; i < pollingTime; i++) {
        let pollRes = (await axios.get(pollUrl)).data;

        if (isNullAny(pollRes.data) || isNullAny(pollRes.data.encryption)) {
            // log('waiting a bit')
            await sleep(1000);
            continue;
        }

        log('Server responds to polling with', pollRes.data);

        return pollRes;
    }

    throw new Error('Polling timeout.');
}

async function pollChunks(dataChainId, userChainId, receiverPubKey) {
    if (window === 'undefined' || defaultRequestId === "ReCheckHAMMER") {
        // TODO: Handle open/decrypt by hammer
    } else {
        idb.init(`recheck-${userChainId}`);

        idb.insert(fileData);
        
        await getDataAndDecrypt(receiverPubKey, putChunkToCache);

        function putChunkToCache(chunkPayload) {
            idb.update(chunkPayload, chunkPayload.dataName);
        }
    }

    // loop and get other chunks
    async function getDataAndDecrypt(dataChainId, receiverPubKey, chunkCallback = null) {
        // get -> data/content -> chunkId: 1, 
        const getUrl = getEndpointUrl('data/content', `dataId=${dataChainId}&chunkId=1`);
        const result = await axios.get(getUrl);
    
        if (!result || result.status !== "OK" || !result.data) {
            throw Error('Error while gettings first chunk!');
        }

        const fileData = result.data;
        const chunksCount = fileData.chunksCount;
        
        // loop chunkCount from result
        for (let i = 1; i <= chunksCount.length; i++) {
            // get chunk data
            let getUrl = getEndpointUrl('data/content', `dataId${dataChainId}&chunkId=${i + 1}`);
            const result = await axios.get(getUrl);

            if (!result || result.status !== "OK" || !result.data) {
                throw Error(`Error on getting chunk data with id ${i + 1}`);
            }

            let decryptedFile = await processEncryptedFileInfo(result.data, receiverPubKey, browserKeyPair.secretEncKey);

            chunkCallback(decryptedFile);
        }    
    
        // after final chunk
        // ...
    }

    const idb = {
        db: null,

        init(dbName = 'recheck') {
            this.db = window.indexedDB.open(dbName);
            
            this.db.onupgradeneeded = (e) => {
                console.log(e)
                this.db = e.target.result;
                this.db.createObjectStore("files", { keyPath: "dataName" })
            }

            this.db.onsuccess = (e) => {
                this.db = e.target.result;
                console.log(e)
            }

            this.db.onerror = (e) => {
                console.log(e)
            }
        },

        add(payload) {
            const tx = this.db.transaction("files", "readwrite");

            tx.onerror = e => alert(`Error! ${e.target.error}`);

            const files = tx.objectStore("files")
            
            files.put(payload);
        },
        
        update(payload, dataName = "") {
            const tx = this.db.transaction("files", "readwrite");
            tx.onerror = e => alert(`Error! ${e.target.error}`);

            const files = tx.objectStore("files")

            const request = files.get(dataName);

            request.onsuccess = (e) => {
                const matching = e.target.result;
                if (matching !== undefined) {
                    let data = matching.payload + payload;
                    files.put(data);
                } else {
                    return; // No match was found.
                }
            };

        }
    }
}

async function pollShare(dataIds, recipients, userId, isExternal = false, functionId = '') {
    if (!Array.isArray(dataIds)) {
        dataIds = [dataIds];
        recipients = [recipients];
    }

    if (dataIds.length !== recipients.length) {
        notificationObject = null;
        throw new Error(`Data count and recipient count mismatch.${functionId}`);
    }

    dataIds = await processExternalId(dataIds, userId, isExternal);

    let recipientType;
    if (recipients.some(r => !isValidEmail(r))) {
        if (recipients.some(r => !isValidAddress(r))) {
            notificationObject = null;
            throw new Error(`Invalid recipient email/id format: ${JSON.stringify(recipients)}`);
        }

        recipientType = 'recipientId';
    } else {
        recipientType = 'recipientEmail'
    }

    if (!isNullAny(functionId)) {
        setShouldWorkPollingForFunctionId(functionId, true);
    }

    let hasSendNotification = false;
    for (let i = 0; i < pollingTime; i++) {
        for (let j = 0; j < dataIds.length; j++) {
            if (!isNullAny(functionId) && !mapShouldBeWorkingPollingForFunctionId[functionId]) {
                notificationObject = null;
                return false;
            }

            let pollUrl = getEndpointUrl('share/info', `&${recipientType}=${recipients[j]}&dataId=${dataIds[j]}`);

            let pollRes = (await axios.get(pollUrl)).data;

            if (isNullAny(pollRes.data)) {
                if (!hasSendNotification) {
                    sendNotification();
                    hasSendNotification = true;
                    notificationObject = null;
                }

                await sleep(1000);
                break;
            } else {
                dataIds.splice(j, 1);
                recipients.splice(j, 1);
                j--;
            }
        }

        if (dataIds.length === 0) {
            setShouldWorkPollingForFunctionId(functionId, false);
            notificationObject = null;
            return functionId || true;
        }
    }

    setShouldWorkPollingForFunctionId(functionId, false);
    notificationObject = null;
    throw new Error(`Share polling timeout...${functionId}`);
}

async function pollEmail(selectionHash, functionId = '') {
    if (isNullAny(selectionHash)) {
        notificationObject = null;
        throw new Error(`Missing selection hash.${functionId}`);
    }

    if (!isNullAny(functionId)) {
        setShouldWorkPollingForFunctionId(functionId, true);
    }

    let pollUrl = getEndpointUrl('email/info', `&selectionHash=${selectionHash}`);

    let hasSendNotification = false;
    for (let i = 0; i < pollingTime; i++) {
        if (!isNullAny(functionId) && !mapShouldBeWorkingPollingForFunctionId[functionId]) {
            notificationObject = null;
            return false;
        }

        let pollRes = (await axios.get(pollUrl)).data;

        if (i === 0 && !isNullAny(pollRes.data) && !pollRes.data.hasNewShare) {
            setShouldWorkPollingForFunctionId(functionId, false);
            notificationObject = null;
            throw new Error(`Recipients already have this data.${functionId}`);
        }

        if (isNullAny(pollRes.data) || isNullAny(pollRes.data.encryptedUrl)) {
            if (!hasSendNotification) {
                sendNotification();
                hasSendNotification = true;
                notificationObject = null;
            }

            await sleep(1000);
        } else {
            setShouldWorkPollingForFunctionId(functionId, false);
            notificationObject = null;
            return functionId || true;
        }
    }

    setShouldWorkPollingForFunctionId(functionId, false);
    notificationObject = null;
    throw new Error(`Email share polling timeout...${functionId}`);
}

async function pollSign(dataIds, userId, isExternal = false, functionId = '') {
    if (!Array.isArray(dataIds)) {
        dataIds = [dataIds];
    }

    dataIds = await processExternalId(dataIds, userId, isExternal);

    if (!isNullAny(functionId)) {
        setShouldWorkPollingForFunctionId(functionId, true);
    }

    let hasSendNotification = false;
    for (let i = 0; i < pollingTime; i++) {
        for (let j = 0; j < dataIds.length; j++) {
            if (!isNullAny(functionId) && !mapShouldBeWorkingPollingForFunctionId[functionId]) {
                notificationObject = null;
                return false;
            }

            let pollUrl = getEndpointUrl('signature/info', `&userId=${userId}&dataId=${dataIds[j]}`);

            let pollRes = (await axios.get(pollUrl)).data;

            if (isNullAny(pollRes.data)) {
                if (!hasSendNotification) {
                    sendNotification();
                    hasSendNotification = true;
                    notificationObject = null;
                }

                await sleep(1000);
                break;
            } else {
                dataIds.splice(j, 1);
                j--;
            }
        }

        if (dataIds.length === 0) {
            setShouldWorkPollingForFunctionId(functionId, false);
            notificationObject = null;
            return functionId || true;
        }
    }

    setShouldWorkPollingForFunctionId(functionId, false);
    notificationObject = null;
    throw new Error(`Signature polling timeout.${functionId}`);
}

async function select(files, recipients, emailShareCommPubKeys = null, isExternal = false) {

    let filteredDataIdsRecipients = [];
    for (let i = 0; i < files.length; i++) {
        let currentDataIdRecipient = files[i] + recipients[i];
        if (filteredDataIdsRecipients.includes(currentDataIdRecipient)) {
            files.splice(i, 1);
            recipients.splice(i, 1);
            i--;
        } else {
            filteredDataIdsRecipients.push(currentDataIdRecipient);
        }
    }

    files = await processExternalId(files, null, isExternal);

    let validateUrl = getEndpointUrl('selection/create');

    let postBody;
    if (recipients.some(r => !isValidEmail(r))) {
        if (recipients.some(r => !isValidAddress(r))) {
            throw new Error(`Invalid recipient email/id format: ${JSON.stringify(recipients)}`);
        }

        postBody = {
            dataIds: files,
            usersIds: recipients,
            usersEmails: null,
        }
    } else {
        if (isNullAny(emailShareCommPubKeys)) {
            throw new Error('Missing public keys for email share browser communication.');
        }

        postBody = {
            dataIds: files,
            usersIds: null,
            usersEmails: recipients,
            pubKey: emailShareCommPubKeys.publicKey,
            pubEncKey: emailShareCommPubKeys.publicEncKey,
        }
    }

    let result = (await axios.post(validateUrl, postBody)).data;

    if (result.status === 'ERROR') {
        throw result.data;
    }

    if (isNullAny(result.data)) {
        throw new Error('Missing result data.');
    }

    if (!isNullAny(emailShareCommPubKeys) && isNullAny(result.data.pubKey, result.data.pubEncKey)) {
        throw new Error('Error posting public keys for email share browser communication.');
    }

    return result.data.selectionHash;
}

async function getSelected(selectionHash) {
    let getUrl = getEndpointUrl('selection/info', `&selectionHash=${selectionHash}`);
    log('getSelected get request', getUrl);

    let selectionResponse = (await axios.get(getUrl)).data;

    if (selectionResponse.status === "ERROR") {
        throw selectionResponse.data;
    }

    return selectionResponse.data;
}

async function prepareSelection(selection, keyPair) {
    if (selection.indexOf(':') <= 0) {// check if we have a selection or an id
        throw new Error('Missing selection operation code.');
    }

    let actionSelectionHash = selection.split(':');
    let action = actionSelectionHash[0];
    let selectionHash = actionSelectionHash[1];

    if (action !== 'op') {
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

async function execSelection(selection, keyPair, txPolling = false, trailExtraArgs = null) {
    this.isWorkingExecReEncr = false;

    if (selection.indexOf(':') <= 0) {// check if we have a selection or an id
        throw new Error('Missing selection operation code.');
    }

    try {
        let actionSelectionHash = selection.split(':');
        let action = actionSelectionHash[0];
        let selectionHash = actionSelectionHash[1];

        let selectionResult = await getSelected(selectionHash);
        log('selection result', selectionResult);

        if (isNullAny(selectionResult.selectionHash)) {
            return [];
        }

        let files = selectionResult.dataIds;
        let recipients = selectionResult.usersIds;
        let emailSharePubKeys = null;
        if (isNullAny(recipients)) {
            if (action !== 'se' || isNullAny(selectionResult.usersEmails)) {
                throw new Error('Invalid selection action/result.');
            }

            recipients = selectionResult.usersEmails;
            recipientsEmailLinkKeyPair = await newKeyPair(null);

            let getUrl = getEndpointUrl('email/info', `&selectionHash=${selectionHash}`);
            let serverResponse = (await axios.get(getUrl)).data;

            if (serverResponse.status === 'ERROR') {
                throw serverResponse.data;
            }

            if (isNullAny(serverResponse.data) || isNullAny(serverResponse.data.pubKey, serverResponse.data.pubEncKey)) {
                throw new Error('Invalid email selection server response.');
            }

            emailSharePubKeys = {pubKey: serverResponse.data.pubKey, pubEncKey: serverResponse.data.pubEncKey};
        }

        if (recipients.length !== files.length) {   // the array sizes must be equal
            throw new Error('Invalid selection format.');
        }

        let hasSendNotification = false;
        let result = [];
        for (let i = 0; i < files.length; i++) {  // iterate open each entry from the array
            switch (action) {
                case 'op':
                    if (keyPair.address !== recipients[i]) {
                        log('selection entry omitted', `${recipients[i]}:${files[i]}`);
                        continue;                             // skip entries that are not for that keypair
                    }

                    if (!isNullAny(keyPair.secretEncKey)) {
                        log('selection entry added', `${recipients[i]}:${files[i]}`);

                        let fileObj = {
                            dataId: files[i]
                        }

                        try {
                            fileObj.data = await open(files[i], keyPair.address, keyPair, false, txPolling, trailExtraArgs);
                        } catch (error) {
                            fileObj.data = error.message ? error.message : error;
                            fileObj.status = "ERROR";
                        }

                        result.push(fileObj);
                    } else {
                        let credentialsResponse = {
                            dataId: files[i],
                            userId: recipients[i]
                        };

                        let fileObj = {
                            dataId: files[i]
                        }

                        if (!hasSendNotification) {
                            sendNotification();
                            hasSendNotification = true;
                            notificationObject = null;
                        }

                        try {
                            fileObj.data = await pollOpen(credentialsResponse, keyPair.publicEncKey, txPolling, trailExtraArgs);
                        } catch (error) {
                            fileObj.data = error.message ? error.message : error;
                            fileObj.status = "ERROR";
                        }


                        this.isWorkingExecReEncr = true;
                        if (fileObj.data === "Polling timeout.") {
                            throw new Error(fileObj.data);
                        }
                        result.push(fileObj);
                    }
                    break;

                case 're':
                    if (keyPair.address !== recipients[i]) {
                        log('selection entry omitted', `${recipients[i]}:${files[i]}`);
                        continue;                      // skip entries that are not for that keypair
                    }

                    log('selection entry added', `${recipients[i]}:${files[i]}`);

                    let scanObj = {
                        dataId: files[i]
                    }

                    try {
                        scanObj.data = await reEncrypt(recipients[i], files[i], keyPair, trailExtraArgs);
                    } catch (error) {
                        scanObj.data = error.message ? error.message : error;
                        scanObj.status = "ERROR";
                    }

                    result.push(scanObj);
                    break;

                case'se':
                case'sh':
                    let shareObj = {
                        dataId: files[i]
                    }

                    try {
                        shareObj.data = await share(files[i], recipients[i], keyPair, false, txPolling, trailExtraArgs, emailSharePubKeys, selectionHash);
                    } catch (error) {
                        shareObj.data = error.message ? error.message : error;
                        shareObj.status = "ERROR";
                    }

                    result.push(shareObj);
                    break;

                case 'sg':
                    let signObj = {
                        dataId: files[i]
                    }

                    try {
                        signObj.data = await sign(files[i], recipients[i], keyPair, false, txPolling, trailExtraArgs);
                    } catch (error) {
                        signObj.data = error.message ? error.message : error;
                        signObj.status = "ERROR";
                    }

                    result.push(signObj);
                    break;

                default:
                    throw new Error('Unsupported selection operation code.');
            }
        }

        return result;

    } catch (error) {
        throw (error);
    } finally {
        recipientsEmailLinkKeyPair = null;
    }
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
    if (isNullAny(pubKey)) {
        return false;
    }

    try {
        switch (network) {
            case "ae":
                let verifyResult = nacl.sign.detached.verify(
                    new Uint8Array(Buffer.from(message)),
                    decodeBase58Check(signature),
                    decodeBase58Check(pubKey.split('_')[1])
                );

                if (verifyResult) {
                    return pubKey;
                }

                return false;

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

async function registerHash(dataChainId, requestType, targetUserId, keyPair, requestId = defaultRequestId, extraTrailHashes = [], txPolling = false, trailExtraArgs = null) {
    if (isNullAny(requestId)) {
        requestId = defaultRequestId;
    }

    if (isNullAny(requestType)) {
        requestType = 'register';
    }

    if (!['upload', 'register', 'ipo_filing', 'bmd_register'].includes(requestType.toLowerCase())) {
        throw new Error("Unsupported request type.");
    }

    let userId = keyPair.address;
    let trailHash = getTrailHash(dataChainId, userId, requestType, targetUserId, trailExtraArgs);

    let body = {
        dataId: dataChainId,
        userId: userId,
        requestId: requestId,
        recipientId: targetUserId,
        requestType: requestType,
        requestBodyHashSignature: 'NULL',
        trailHash: trailHash,
        trailHashSignatureHash: getHash(signMessage(trailHash, keyPair.secretKey)),
        extraTrailHashes: extraTrailHashes
    };

    body.requestBodyHashSignature = signMessage(getRequestHash(body), keyPair.secretKey);

    let postUrl = getEndpointUrl('tx/create');
    log('registerHash, ', body);

    let serverPostResponse = (await axios.post(postUrl, body)).data;
    log('Server responds to registerHash POST', serverPostResponse.data);

    if (serverPostResponse.status === "ERROR") {
        throw serverPostResponse.data;
    }

    if (!txPolling) {
        return serverPostResponse.data;
    }

    return await processTxPolling(dataChainId, userId, 'requestId', requestId);
}

async function checkHash(dataChainId, userId, requestId = null, isExternal = false) {

    dataChainId = await processExternalId(dataChainId, userId, isExternal);

    let query = `&userId=${userId}&dataId=${dataChainId}`;

    if (!isNullAny(requestId)) {
        query += `&requestId=${requestId}`;
    }

    let getUrl = getEndpointUrl('tx/info', query);
    log('query URL', getUrl);

    let serverResponse = (await axios.get(getUrl)).data;
    log('Server responds to checkHash GET', serverResponse.data);

    return serverResponse.data;
}

async function saveExternalId(externalId, userChainId, dataOriginalHash = null) {

    let body = {
        externalId: externalId,
        userId: userChainId,
        dataOriginalHash: dataOriginalHash,
    };

    let postUrl = getEndpointUrl('data/id/create');
    log('saveExternalId, ', body);

    let serverPostResponse = (await axios.post(postUrl, body)).data;
    log('Server responds to saveExternalId POST', serverPostResponse.data);

    if (serverPostResponse.status === "ERROR") {
        throw serverPostResponse.data;
    }

    return serverPostResponse.data;
}

async function convertExternalId(externalId, userId) {
    let query = `&userId=${userId}&externalId=${externalId}`;

    let getUrl = getEndpointUrl('data/id/info', query);
    log('query URL', getUrl);

    let serverResponse = (await axios.get(getUrl)).data;
    log('Server responds to convertExternalId GET', serverResponse.data);

    if (serverResponse.status === "ERROR") {
        throw serverResponse.data;
    }

    return serverResponse.data;
}

function setShouldWorkPollingForFunctionId(functionId, value) {
    mapShouldBeWorkingPollingForFunctionId[functionId] = value;
}

async function createShortQueryUrl(url) {

    let basePath = url.substr(0, url.lastIndexOf('/') + 1);
    let fragment = url.substr(url.lastIndexOf('#'));
    let pathQuery = url.replace(basePath, '').replace(fragment, '');

    let body = {
        longQuery: pathQuery,
    };

    let postUrl = getEndpointUrl('email/share/url/create');
    log('createShortUrl, ', body);

    let serverPostResponse = (await axios.post(postUrl, body)).data;
    log('Server responds to createShortUrl POST', serverPostResponse.data);

    if (serverPostResponse.status === "ERROR"
        || isNullAny(serverPostResponse.data) || isNullAny(serverPostResponse.data.shortQuery)) {
        throw serverPostResponse.data;
    }

    return basePath + serverPostResponse.data.shortQuery + fragment;
}

async function getLongQueryUrl(queryHash) {
    let query = `&queryHash=${queryHash}`;

    let getUrl = getEndpointUrl('email/share/url/info', query);
    log('query URL', getUrl);

    let serverResponse = (await axios.get(getUrl)).data;
    log('Server responds to getLongQueryUrl GET', serverResponse.data);

    if (serverResponse.status === "ERROR"
        || isNullAny(serverResponse.data) || isNullAny(serverResponse.data.longQuery)) {
        throw serverResponse.data;
    }

    return serverResponse.data.longQuery;
}

function setNotificationObject(selectionActionHash, challenge = null) {
    notificationObject = {selectionActionHash, challenge};
}

function sendNotification() {
    let notificationUrl = getEndpointUrl('user/notification');

    if (!isNullAny(notificationObject)) {
        axios.post(notificationUrl, notificationObject)
            .then((result) => {
                logDebug('notification', result)
            });
    }

    notificationObject = null;
}


module.exports = {
    encryptDataToPublicKeyWithKeyPair: encryptDataToPublicKeyWithKeyPair,
    decryptDataWithPublicAndPrivateKey: decryptDataWithPublicAndPrivateKey,
    processEncryptedFileInfo: processEncryptedFileInfo,
    isNullAny: isNullAny,
    getHash: getHash,
    getHashOld: getHashOld,
    getHashFromHashObject: getHashFromHashObject,
    getUpdatedHashObj: getUpdatedHashObj,
    getRequestHash: getRequestHash,
    getTrailHash: getTrailHash,

    debug: setDebugMode,
    setDefaultRequestId: setDefaultRequestId,
    /* Specify API token and API host */

    init: init,
    //get server info - api version/current blockchain type
    getServerInfo: getServerInfo,
    // login i login with challenge
    // login hammer 0(account) 0x.. (challenge code)
    // node hammer login 1 (second user's login)
    getLoginChallenge: getLoginChallenge,
    login: login,
    loginWithChallenge: loginWithChallenge,

    /* Create a keypair and recovery phrase */
    newKeyPair: newKeyPair,

    /* Encrypt, upload and register a file or any data */
    //upload new file
    store: store,
    storeData: storeData,
    storeLargeFiles: storeLargeFiles,
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
    // browser poll for sharing
    pollShare: pollShare,
    // browser poll for email sharing
    pollEmail: pollEmail,

    sign: sign,
    // browser poll for signing
    pollSign: pollSign,

    /* Retrieve file - used in case of browser interaction */
    // submit credentials of the decrypting browser
    prepare: prepare,
    // decrypt password and re-encrypt for decrypting browser
    reEncrypt: reEncrypt,
    // polling on the side of decrypting browser for encrypted file
    pollOpen: pollOpen,

    // node hammer select-share 0x...(fileID) 2k_...(recipient) 0(sender) returns "s:qrCode"
    select: select,
    selection: getSelected,
    prepareSelection: prepareSelection,
    // node hammer exec o:0x...(selection hash)
    execSelection: execSelection,
    isWorkingExecReEncr: isWorkingExecReEncr,

    signMessage: signMessage,
    verifyMessage: verifyMessage,

    registerHash: registerHash,
    checkHash: checkHash,

    saveExternalId: saveExternalId,
    convertExternalId: convertExternalId,

    setShouldWorkPollingForFunctionId: setShouldWorkPollingForFunctionId,

    createShortQueryUrl: createShortQueryUrl,
    getLongQueryUrl: getLongQueryUrl,

    setNotificationObject: setNotificationObject,
    sendNotification: sendNotification,
};
