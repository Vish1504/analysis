
const rsaAnalysis = (message) => {
    const crypto = require('crypto');


    const encryptionKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);

    const memoryUsageBefore = process.memoryUsage().heapUsed;
    // RSA KeyGen
    let startTime = new Date();
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
        modulusLength: 2048,
    });
    const pubkey = publicKey.export({
        type: "spki",
        format: "pem",
    });
    const privkey = privateKey.export({
        type: "pkcs8",
        format: "pem",
    });
    let rsaRanTime = new Date() - startTime;

    // AES Encryption
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(encryptionKey), iv);
    let aes_encrypted = cipher.update(message, 'utf8', 'base64');
    aes_encrypted += cipher.final('base64');


    // RSA Encryption of AES encrypted text
    startTime = new Date();
    const RSAmessage = encryptionKey;
    const encryptedData = crypto.publicEncrypt(
        {
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        },
        Buffer.from(RSAmessage)
    );
    let rsaEncTime = new Date() - startTime;

    // RSA Decryption of RSA encrypted text
    startTime = new Date();
    const decryptedData = crypto.privateDecrypt(
        {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        },
        encryptedData
    );
    let rsaDecTime = new Date() - startTime;

    // AES Decryption of RSA Decrypted text

    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(decryptedData), iv);
    let aes_decrypted = decipher.update(aes_encrypted, 'base64', 'utf8');
    aes_decrypted += decipher.final('utf8');

    // Log the AES decrypted text and the time taken by each step
    // console.log('\nDecrypted message: ' + aes_decrypted);

    // console.log(`RSA key generation time: ${rsaRanTime}ms`);

    // console.log(`RSA encryption time: ${rsaEncTime}ms`);
    // console.log(`RSA decryption time: ${rsaDecTime}ms`);
    const memoryUsageAfter = process.memoryUsage().heapUsed;
    const memoryConsumed = memoryUsageAfter - memoryUsageBefore;


    return { aes_decrypted, rsaRanTime, rsaEncTime, rsaDecTime, memoryConsumed };
};


const mcelieceAnalysis = (message) => {

    var mceliece = require("./mceliece");

    const crypto = require('crypto');
    const memoryUsageBefore = process.memoryUsage().heapUsed;
    // Generate a 32-byte AES key
    const encryptionKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);

    // Start measuring keygen time
    const keygenStartTime = Date.now();

    // Generate a McEliece key pair
    const keyPair = mceliece.keyPair();

    // Stop measuring keygen time
    const keygenEndTime = Date.now();
    const keygenTime = keygenEndTime - keygenStartTime;


    // Start measuring encryption time
    const encryptionStartTime = Date.now();

    // Encrypt the message using the AES key
    const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, iv);
    let aesEncrypted = cipher.update(message, 'utf8', 'base64');
    aesEncrypted += cipher.final('base64');

    // Encrypt the AES key using McEliece
    const aesKeyArray = new Uint8Array(encryptionKey);
    const encryptedAesKey = mceliece.encrypt(aesKeyArray, keyPair.publicKey);

    // Stop measuring encryption time
    const encryptionEndTime = Date.now();
    const encryptionTime = encryptionEndTime - encryptionStartTime;


    // Start measuring decryption time
    const decryptionStartTime = Date.now();

    // Decrypt the AES key using McEliece
    const decryptedAesKeyArray = mceliece.decrypt(encryptedAesKey, keyPair.privateKey);
    const decryptedAesKey = Buffer.from(decryptedAesKeyArray).toString('hex');

    // Decrypt the message using the decrypted AES key
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(decryptedAesKey, 'hex'), iv);
    let aesDecrypted = decipher.update(aesEncrypted, 'base64', 'utf8');
    aesDecrypted += decipher.final('utf8');

    // Stop measuring decryption time
    const decryptionEndTime = Date.now();
    const decryptionTime = decryptionEndTime - decryptionStartTime;


    // console.log('Mceliece decrypted message: ' + aesDecrypted);
    // console.log('keygen time: ' + keygenTime + 'ms');
    // console.log('encryption time: ' + encryptionTime + 'ms');
    // console.log('decryption time: ' + decryptionTime + 'ms');
    const memoryUsageAfter = process.memoryUsage().heapUsed;
    const memoryConsumed = memoryUsageAfter - memoryUsageBefore;
    return {
        aesDecrypted, keygenTime, encryptionTime, decryptionTime, memoryConsumed
    };
};

const kyberAnalysis = (message) => {
    const crypto = require('crypto');
    const kyber = require('crystals-kyber');

    const memoryUsageBefore = process.memoryUsage().heapUsed;

    // Start measuring keygen time
    const keygenStartTime = Date.now();

    // To generate a public and private key pair (pk, sk)Kyber
    const pk_sk = kyber.KeyGen768();
    const pk = pk_sk[0];
    const sk = pk_sk[1];

    // Stop measuring keygen time
    const keygenEndTime = Date.now();
    const keygenTime = keygenEndTime - keygenStartTime;

    // Start measuring encryption time
    const encryptionStartTime = Date.now();

    // To generate a random 256-bit symmetric key (ss) and its encapsulation (c)
    const c_ss = kyber.Encrypt768(pk);
    const c = c_ss[0];
    const ss1 = c_ss[1];

    const iv = crypto.randomBytes(16); // 128-bit initialization vector

    // Generate a new initialization vector for each message
    const newIv = crypto.randomBytes(16);

    // Encrypt the message with the symmetric key and the new initialization vector
    const cipher = crypto.createCipheriv('aes-256-cbc', ss1, newIv);
    let encrypted = cipher.update(message, 'utf8', 'base64');
    encrypted += cipher.final('base64');

    // Stop measuring encryption time
    const encryptionEndTime = Date.now();
    const encryptionTime = encryptionEndTime - encryptionStartTime;

    // Start measuring decryption time
    const decryptionStartTime = Date.now();

    // Generate a new symmetric key using the encapsulation and the private key
    const ss2 = kyber.Decrypt768(c, sk);

    // Decrypt the message with the new symmetric key and the new initialization vector
    const decryptedCipher = crypto.createDecipheriv('aes-256-cbc', ss2, newIv);
    let decrypted = decryptedCipher.update(encrypted, 'base64', 'utf8');
    decrypted += decryptedCipher.final('utf8');

    // Stop measuring decryption time
    const decryptionEndTime = Date.now();
    const decryptionTime = decryptionEndTime - decryptionStartTime;

    const memoryUsageAfter = process.memoryUsage().heapUsed;
    const memoryConsumed = Math.abs(memoryUsageAfter - memoryUsageBefore);

    return { decrypted, keygenTime, encryptionTime, decryptionTime, memoryConsumed };
};


module.exports = { rsaAnalysis, mcelieceAnalysis, kyberAnalysis };
