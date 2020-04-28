# HTTP API calls 
All of the information is sent via JSON format. In the code we have a function to write the full url before the call where for the test environtment the baseUrl is being "https://beta.recheck.io" :
```
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
```

## API/GET 

### **login/check** 
This request is called when asking for info about the blockchain and version of the service

- usage - http://localhost:3000/login/check?noapi=1
- returns 
```
{ apiVersion: '1',
  blockchain: 'ae',
  contractAddress: 'ct_L1faE2uDpK9XtUYHv9Vrr4JdwC6s2sPwbMP97uT9YPGuJq1GK' }
```
### **login/challenge**

This request is called for server connection to then pass it to a post request - mobile/login - to get a token. Which is needed for more complicated APIs. Called in _login(keyPair)_

- usage http://localhost:3000/login/challenge?noapi=1
- response - gives information about the status of the call, the network, api, contract address and is about to pass the challenge field to the "login/mobile" POST request. 
``` 
{ status: 'OK',
  code: 200,
  apiVersion: '1',
  blockchain: 'ae',
  contractAddress: 'ct_L1faE2uDpK9XtUYHv9Vrr4JdwC6s2sPwbMP97uT9YPGuJq1GK',
  data: 
   { challenge: '0x2eb05eb811421dd56557833144ec1e96577566d85196f7ce6f5442af2fd4697e',
     uuid: '61342ef0-8881-11ea-8313-2b73e6c31f3b',
     startTimestamp: '2020-04-27T12:19:45.120Z',
     endTimestamp: '2020-04-27T12:34:45.120Z' 
    } 
}
```

### credentials/share
This request is called in _share()_. The server responds with recipient and data about decryption for the recipient.

- usage 
    - getEndpointUrl('credentials/share', `&dataId=${dataId}&recipientId=${recipientId}`)
    - http://localhost:3000/credentials/share?api=1&token=f7162e90-8887-11ea-8313-2b73e6c31f3b&dataId=0x3d56619d858b2e6f31b12b295c17b6f19da53f91df758c51408c01bc0fa23da5&recipientId=ak_2YNSqPZ1th7MosxSQh4mjLs6QkYT9QJmWCXzaRzKEtf5eaiL2W

- returns 
```
{ 
  status: 'OK',
  code: 200,
  apiVersion: '1',
  blockchain: 'ae',
  contractAddress: 'ct_L1faE2uDpK9XtUYHv9Vrr4JdwC6s2sPwbMP97uT9YPGuJq1GK',
  data: 
   { 
    dataId: '0x3d56619d858b2e6f31b12b295c17b6f19da53f91df758c51408c01bc0fa23da5',
    encryption: 
      { 
        encryptedPassA: 'y0pjZx3r/zk9f6CcQmIvKwWHsAm1DTZc7n0Vl0NaNcMZM1wEZKg9s9U352IuK2Bi4fVnYsNCpH6wYjy7K13ntdKsrDPEkdJTA27wG6O4mOvXeJr2',
        pubKeyA: '2bp7KqG2hjdPyWnKuAaBA89H1YNpN5SRkE3jxkU8oj8Ck2nHNN',
        recipientEncrKey: '2KsyaLVqnadzxMjEC5fSt3KMLKCeyL3zmE91MHXTMrVw5HW7BZ' 
      },
    recipientId: 'ak_2YNSqPZ1th7MosxSQh4mjLs6QkYT9QJmWCXzaRzKEtf5eaiL2W' 
   } 
}
```

### credentials/exchange
This request is called in _reEncrypt()_ it asks for the browser's credentials. It is the one from you are opening/downloading the file.

- usage 
    - 
    let query = `&userId=${userId}&dataId=${dataChainId}&requestId=${defaultRequestId}&requestType=${requestType}&requestBodyHashSignature=NULL&trailHash=${trailHash}&trailHashSignatureHash=${trailHashSignatureHash}`;
    let getUrl = getEndpointUrl('credentials/exchange', query);
    -  http://localhost:3000/credentials/exchange?api=1&token=61101fa0-8896-11ea-8313-2b73e6c31f3b&userId=ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5&dataId=0x3d56619d858b2e6f31b12b295c17b6f19da53f91df758c51408c01bc0fa23da5&requestId=ReCheck&requestType=download&requestBodyHashSignature=DFi3iatmDRN7PNVovchzMRbqUYo97Xo7EHUxumweBfionGG7PxvtAww9wPXdw5SSqR63sHXVTFpXwbDv4ix6p4riSA1JW&trailHash=0xda2d928dc31c1f107bf73a14ea25815abd4a3f76d7dc90bae21b5d551f603e56&trailHashSignatureHash=0xec3fb1f9f6bba8b113905ac17a8dc46e318fe9311701b26c42732ba88ca8b0b6
- response 
```
{ status: 'OK',
  code: 200,
  apiVersion: '1',
  blockchain: 'ae',
  contractAddress: 'ct_L1faE2uDpK9XtUYHv9Vrr4JdwC6s2sPwbMP97uT9YPGuJq1GK',
  data: 
   { dataId: '0x3d56619d858b2e6f31b12b295c17b6f19da53f91df758c51408c01bc0fa23da5',
     userId: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5',
     encryption: 
      { encryptedPassA: 'y0pjZx3r/zk9f6CcQmIvKwWHsAm1DTZc7n0Vl0NaNcMZM1wEZKg9s9U352IuK2Bi4fVnYsNCpH6wYjy7K13ntdKsrDPEkdJTA27wG6O4mOvXeJr2',
        pubKeyA: '2bp7KqG2hjdPyWnKuAaBA89H1YNpN5SRkE3jxkU8oj8Ck2nHNN',
        pubKeyB: '2XtBHxmnh3fjNuWgU4jQXNh7v3oB5CtYPoYtDCr8JpdQNiNBk8' 
        } 
    } 
}
```

### data/info

- usage
- returns

### share/info

- usage 
- returns

### selection
This request is called in _getSelected_ in order to get the selection hash of the selected files.

- usage
  - getEndpointUrl('selection', `&selectionHash=${selectionHash}`)
  - http://localhost:3000/selection?api=1&token=25a47120-8934-11ea-8721-bf12354c64b8&selectionHash=0x0758d99c69e463c5fcce17c418cbe9efd4371a2adfd5f42c042cac178bbbd633
- returns 
```
{ 
  status: 'OK',
  code: 200,
  apiVersion: '1',
  blockchain: 'ae',
  contractAddress: 'ct_L1faE2uDpK9XtUYHv9Vrr4JdwC6s2sPwbMP97uT9YPGuJq1GK',
  data: 
   { selectionHash: '0x0758d99c69e463c5fcce17c418cbe9efd4371a2adfd5f42c042cac178bbbd633',
     dataIds: 
      [ '0x9eeb588e1f8a6185d3d9b3da92298836c18933f8b822735b7a01b45a17b96819' ],
     usersIds: [ 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5' ] 
    } 
}
```
### signature/info

- usage
- returns

### tx/check
This request is called in _checkHash_. 

- usage
http://localhost:3000/tx/check?api=1&token=2eb3e900-8946-11ea-aee2-33022313c596&userId=ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5&dataId=0xb9a5dc0048db9a7d13548781df3cd4b2334606391f75f40c14225a92f4cb3537
- returns 

```
{ status: 'OK',
  code: 200,
  apiVersion: '1',
  blockchain: 'ae',
  contractAddress: 'ct_L1faE2uDpK9XtUYHv9Vrr4JdwC6s2sPwbMP97uT9YPGuJq1GK',
  data: 
   [ { txRowId: 18,
       dataId: '0xb9a5dc0048db9a7d13548781df3cd4b2334606391f75f40c14225a92f4cb3537',
       userId: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5',
       recipientId: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5',
       requestId: 'ReCheck',
       requestType: 'register',
       requestBody: [Object],
       requestBodyHashSignature: 'QWTfZbiaF4uL8RxoMnrzsCtonPbbVGQEb24FYcxT5h6gTNEMk7SmHbJcN5pXmFYbGhzryFnpXvgEGz3ivGsWRh7L5whwS',
       trailHash: '0x0e8b0e38684020111e1f10ce179058fb69e48addb94173e1520404c1d2798788',
       trailHashSignatureHash: '0x09eb43432605bb66ecb84bc4829e7a24a76dc1b1379e6be719cb8f40318cdaf1',
       extraTrailHashes: [],
       executorId: 'ak_mEMRng9eTTwqkwJGnrDm79pnoi559YPBv3eXX1iphT6hxNemf',
       contractId: 'ct_L1faE2uDpK9XtUYHv9Vrr4JdwC6s2sPwbMP97uT9YPGuJq1GK',
       txHash: 'th_Aesk4ssdwJ4bkh7GQRf8qLDL36X4znMKtuw1vb6AdiybSK119',
       txReceipt: [Object],
       txReceiptTimestamp: '2020-04-28T11:46:27.000Z',
       txAttempts: 1,
       txAttemptTimestamp: '2020-04-28T11:46:27.000Z',
       txStatus: 'complete',
       dateCreated: '2020-04-28T11:46:17.000Z',
       dateUpdated: '2020-04-28T11:46:27.000Z' 
      } 
    ]
}
```

### data/id

- usage
- returns
------------------
## API/POST 

### login/mobile

This request is called in _loginWithChallenge_ to get the token. 

- usage http://localhost:3000/login/mobile?noapi=1
- body 
```
{ 
  action: 'login',
  pubKey: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5',
  pubEncKey: '2pYnhELKZnC4Ykg8YwE9zKRTnzcN2dbkNzFQhn6qR7fcmkoSZ5',
  firebase: 'notoken',
  challenge: '0xba739785f23fe4f450a42b7c88910bf294bfdac8e6af4d17b79cbb50ffd1fa74',
  challengeSignature: 'Bo8uMnbNyxgEo2NB7KVqzCvftgwudpquc6XXd63G3XsnLLYr9H3eNHGpmMedCd3mDMit2bLLYkd4YdJcVyWtHUUD9KgcK',
  rtnToken: 'notoken' 
}
```
- returns info about the network along with the rtnToken needed for the more complex calls 
```
{ status: 'OK',
  code: 200,
  apiVersion: '1',
  blockchain: 'ae',
  contractAddress: 'ct_L1faE2uDpK9XtUYHv9Vrr4JdwC6s2sPwbMP97uT9YPGuJq1GK',
  data: 
   { 
    rtnToken: '1c9e8480-8885-11ea-8313-2b73e6c31f3b',
     rtnTokenHash: '0x5c86a6a658c25fea85d3ad246b8b5da10a7ae87f8702b8e81720793484b47684'  
   }
}
     
```

### tx/create
Used in _registerHash()_.

- usage
http://localhost:3000/tx/create?api=1&token=5bd361f0-8945-11ea-aee2-33022313c596
- body 
```
{ dataId: '0x9eeb588e1f8a6185d3d9b3da92298836c18933f8b822735b7a01b45a17b96819',
  userId: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5',
  requestId: 'ReCheck',
  recipientId: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5',
  requestType: 'register',
  requestBodyHashSignature: '4qGkoR3HhoS1bDbFjqN7xsugeWpy5UQbUBvdvn34PDRtuU22nA6icaKwGgAN9CuKSu4KqK4vWPLrmpLSy5k6XTvAAxczb',
  trailHash: '0xce6266a996b7c2e132cd6460f95c9fc4bec07e1f370f220068da3e48dde94258',
  trailHashSignatureHash: '0xd51329fac25d9ca419462a6519ef3aaf7317e53a8412ab84b1a44ddcb170979a',
  extraTrailHashes: [] 
}
```
- returns
```
{ status: 'OK',
  code: 200,
  apiVersion: '1',
  blockchain: 'ae',
  contractAddress: 'ct_L1faE2uDpK9XtUYHv9Vrr4JdwC6s2sPwbMP97uT9YPGuJq1GK',
  data: 
   { dataId: '0xb9a5dc0048db9a7d13548781df3cd4b2334606391f75f40c14225a92f4cb3537',
     userId: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5' 
    } 
}
```
### selection/create
Used in _select_

- usage
- body 
- returns

### credentials
This request is called in _prepare()_ to give half of the password to the browser, which it then to pass to the recipient.

- usage
http://localhost:3000/credentials?api=1&token=a89a6d30-893b-11ea-aee2-33022313c596
- body
```
 { dataId: '0x9eeb588e1f8a6185d3d9b3da92298836c18933f8b822735b7a01b45a17b96819',
  userId: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5',
  encryption: 
   { pubKeyB: '2kQ4bUJ4c1D75tJayYHnk5nzLbdZtUk1ZuL6bgLVZD8s7VCcZR' } }
```
- returns
```
{ status: 'OK',
  code: 200,
  apiVersion: '1',
  blockchain: 'ae',
  contractAddress: 'ct_L1faE2uDpK9XtUYHv9Vrr4JdwC6s2sPwbMP97uT9YPGuJq1GK',
  data: 
   { dataId: '0x9eeb588e1f8a6185d3d9b3da92298836c18933f8b822735b7a01b45a17b96819',
     userId: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5' 
    } 
}
```
### signature/create
This request is called in _sign()_. Takes a file and puts a "signature" on it. 

- usage
http://localhost:3000/signature/create?api=1&token=25a47120-8934-11ea-8721-bf12354c64b8
- body
```
{ dataId: '0x9eeb588e1f8a6185d3d9b3da92298836c18933f8b822735b7a01b45a17b96819',
  userId: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5',
  requestId: 'ReCheck',
  recipientId: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5',
  requestType: 'sign',
  requestBodyHashSignature: '2sGAFRavHeAfpjfECNRu1cxyKskhvNgWfx94zgzHYFxkHBPNyxKaL6crV1cX8ZPnqP746fA8WjbjSEykaVKynA29SZihL',
  trailHash: '0x26f4cbc7d79a784441a5b471644149ffa62e4eb9b6915ec3a344df915c983e16',
  trailHashSignatureHash: '0xcc1368f076a5e63012074ca2d5497e8898ab56acaced47927f27a88fb8230887' 
  }
```

- returns
```
{ 
  status: 'OK',
  code: 200,
  apiVersion: '1',
  blockchain: 'ae',
  contractAddress: 'ct_L1faE2uDpK9XtUYHv9Vrr4JdwC6s2sPwbMP97uT9YPGuJq1GK',
  data: 
   { dataId: '0x9eeb588e1f8a6185d3d9b3da92298836c18933f8b822735b7a01b45a17b96819',
     userId: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5' 
    } 
}
```
### credentials/validate
This request is called in _validate()_

- usage
 http://localhost:3000/credentials/validate?api=1&token=a89a6d30-893b-11ea-aee2-33022313c596
- body 
```
{ userId: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5',
  dataId: '0x9eeb588e1f8a6185d3d9b3da92298836c18933f8b822735b7a01b45a17b96819',
  requestId: 'ReCheck',
  requestType: 'verify',
  requestBodyHashSignature: '0xf2dc78f28d0c3f9f54772a3e1ef159c26bef5352740398ab787d79a863d41d18',
  trailHash: '0x2d51da7f5861decb9869e3d5fc387149966e5073218849067cca352d1cfb5fcc',
  trailHashSignatureHash: '0x662f4ef2000a0ee651a352dfbb77ebbe55afc2fd90ab79f3dab726460f95c6fc',
  encryption: 
   { decrDataOrigHash: '0xa67f0c7a5f4c955ebcb9a4c110ec557b2324bb3c28ccfdc52ff8adb229d0daa6' } }
```
- returns 
```
{ status: 'OK',
  code: 200,
  apiVersion: '1',
  blockchain: 'ae',
  contractAddress: 'ct_L1faE2uDpK9XtUYHv9Vrr4JdwC6s2sPwbMP97uT9YPGuJq1GK',
  data: 
   { dataId: '0x9eeb588e1f8a6185d3d9b3da92298836c18933f8b822735b7a01b45a17b96819',
     userId: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5' 
   } 
}
```

### data/create
This request is called in _store_ upon uploading data to the server. 

- usage
http://localhost:3000/data/create?api=1&token=0dc43000-8933-11ea-8721-bf12354c64b8
- body
```
{ userId: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5',
  dataId: '0x9eeb588e1f8a6185d3d9b3da92298836c18933f8b822735b7a01b45a17b96819',
  requestId: 'ReCheck',
  requestType: 'upload',
  requestBodyHashSignature: '0x2d13e92e50753deca2ac5f669029f36723a5226be647892f209e613e858530a4',
  trailHash: '0xf0fc1230e929f365f622e87fe4cc63391d2601df97f1ad7b7ece0361448fed10',
  trailHashSignatureHash: '0x4b9a0a487d1d930ef746d8e42902429a15c2c4035a81af16ec83b3fd62f2c5ee',
  dataName: 'data',
  dataExtension: '.png',
  category: undefined,
  keywords: undefined,
  payload: '9CV9QIuUrciJk8NSc1olAn46UqlvyXXkM8B91WODbV3LJ2rnS3HfB7M7cbRWizy/VJa6+VVc2Suy3ez9Aama4PxiziLpkUHFQXPG+M7Msb4QP5tw9arTP1buWt3K0Ld2zbClK5LduzNkEPzBrTegKyE2nEButw7ezDdrX7+7ungomrIF//uuhZfhg5GkYEQT6fS2JUNyCHGwYopxmmIt7HyrHsecye0EAjNdF3mKwIVH+0w3mJnb/mDFDVeJrOHCE4IvE91Swsrg2au/O+/L4+PVu4Ul4DfEprMScHBybkkLMJe5AwnwMLlVM... ',
  encryption: 
   { dataOriginalHash: '0xa67f0c7a5f4c955ebcb9a4c110ec557b2324bb3c28ccfdc52ff8adb229d0daa6',
     salt: '5gjd1h04aFJQ6mN53DZJd87uQ3OolIocgXp+Qs6xFrc=',
     passHash: '0xb9eb715dd33b26c1a9dfd315944090cb0993357e6524a5699a32519694f93447',
     encryptedPassA: 'ZwqycpMURsAdqvuUD2jQpsYaVs/URleAXPYl2rVqD8VPQi+v6zNEozc584FZgeYN7iiXqUrM6Qju2uYY8vWvvx5+y0sF18nkjeAVMXsEX9qb5VTh',
     pubKeyA: 'AmWNogUCi8xtjjHtw7bWLLarAAVAXP4EpXZJb2ffEetj9mZyE' 
   } 
}
```
- return
  { status: 'OK',
  code: 200,
  apiVersion: '1',
  blockchain: 'ae',
  contractAddress: 'ct_L1faE2uDpK9XtUYHv9Vrr4JdwC6s2sPwbMP97uT9YPGuJq1GK',
  data: 
   { dataId: '0x9eeb588e1f8a6185d3d9b3da9 2298836c18933f8b822735b7a01b45a17b96819',
     userId: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5' 
   }
}

### credentials/exchange
This post request is called in _reEncrypt_ to reEncrypt the chosen file(s) for the selected user 

- usage - http://localhost:3000/credentials/exchange?api=1&token=61101fa0-8896-11ea-8313-2b73e6c31f3b
- body 
```
{ dataId: '0x3d56619d858b2e6f31b12b295c17b6f19da53f91df758c51408c01bc0fa23da5',
  userId: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5',
  encryption: 
   { syncPassHash: '0xa6a4f9cca18efbe3eb4909eeda8c62967dd20fc0ee4e4c5b9835bb2f7d37c68f',
     encryptedPassB: 'MRlc8BfgXaqwpaQaDiGdsqWkmUfDm2MD7dtCvmKwGBT7kK+CsepkAsZcIUZxRviYlDmDCL0iEJbeaPVOR0jIBZRqxw9uiPtSeelJy0kHNgFnCJmD' } }
```

-responce 

```
{ status: 'OK',
  code: 200,
  apiVersion: '1',
  blockchain: 'ae',
  contractAddress: 'ct_L1faE2uDpK9XtUYHv9Vrr4JdwC6s2sPwbMP97uT9YPGuJq1GK',
  data: 
   { dataId: '0x3d56619d858b2e6f31b12b295c17b6f19da53f91df758c51408c01bc0fa23da5',
     userId: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5' } }
```

### share/create
This request is called in _share()_. Posts to the server the specific data you want to share with the specific parties. 

- usage 
    - http://localhost:3000/share/create?api=1&token=f7162e90-8887-11ea-8313-2b73e6c31f3b
- body 
```
 { userId: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5',
  dataId: '0x3d56619d858b2e6f31b12b295c17b6f19da53f91df758c51408c01bc0fa23da5',
  requestId: 'ReCheck',
  requestType: 'share',
  requestBodyHashSignature: '37FtVEKZ6rvGVHE4k2vZ8mdUzGeYhhSZwAja7H3R8KERy5tLP31XADcH7EUShGDZ66AbHsMdsBjAnAnoxMjwjn5iMDVrk',
  trailHash: '0x36ec436b215fd89bc7ce2f38ddf3c9bc0e63271f62868a9e5f16f45d0fb5b64e',
  trailHashSignatureHash: '0x2bb536ff04b0f64897fe5eaff0704f08b69cf85544dcadfb0d93e76e4edec269',
  recipientId: 'ak_2YNSqPZ1th7MosxSQh4mjLs6QkYT9QJmWCXzaRzKEtf5eaiL2W',
  encryption: 
   {
     senderEncrKey: '2pYnhELKZnC4Ykg8YwE9zKRTnzcN2dbkNzFQhn6qR7fcmkoSZ5',
     syncPassHash: '0xa6a4f9cca18efbe3eb4909eeda8c62967dd20fc0ee4e4c5b9835bb2f7d37c68f',
     encryptedPassA: 'OlMjI32h0DA8hBcy9TazubUM47wKanT7Z+lC1so1JfMn4LIik+Td8PM9YW+BwDAVJH8PkjEfOSOH78iMOhs5yfpyhNo7XU/LPbpnp1m3+ttZouDH' 
    } 
}
```
- response
```
{ 
  status: 'OK',
  code: 200,
  apiVersion: '1',
  blockchain: 'ae',
  contractAddress: 'ct_L1faE2uDpK9XtUYHv9Vrr4JdwC6s2sPwbMP97uT9YPGuJq1GK',
  data: 
   { 
     dataId: '0x3d56619d858b2e6f31b12b295c17b6f19da53f91df758c51408c01bc0fa23da5',
     userId: 'ak_ApGfbxjgRLrHzHsKXXmTrpX6h9QvRwTfC8GBKsD4ojBapKoE5',
     notification: 'notoken' 
    } 
}
```

