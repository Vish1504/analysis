const express = require('express');
const app = express();
const { rsaAnalysis } = require('./results');
const { mcelieceAnalysis } = require('./results');
const { kyberAnalysis } = require('./results');
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});


app.post('/analyse', function (req, res) {
    const message = req.body.message;

    const rsaResult = rsaAnalysis(message);
    const mcelieceResult = mcelieceAnalysis(message);
    const kyberResult = kyberAnalysis(message);

    res.send(`
            <h1>RSA</h1>
            <p>Decrypted message: ${rsaResult.aes_decrypted}</p>
            <p>RSA key generation time: ${rsaResult.rsaRanTime}ms</p>
            <p>RSA encryption time: ${rsaResult.rsaEncTime}ms</p>
            <p>RSA decryption time: ${rsaResult.rsaDecTime}ms</p>
    
            <h1>McEliece</h1>
            <p>Decrypted message: ${mcelieceResult.aesDecrypted}</p>
            <p>McEliece key generation time: ${mcelieceResult.keygenTime}ms</p>
            <p>McEliece encryption time: ${mcelieceResult.encryptionTime}ms</p>
            <p>McEliece decryption time: ${mcelieceResult.decryptionTime}ms</p>
    
            <h1>Kyber</h1>
            <p>Decrypted message: ${kyberResult.decrypted}</p>
            <p>Kyber key generation time: ${kyberResult.keygenTime}ms</p>
            <p>Kyber encryption time: ${kyberResult.encryptionTime}ms</p>
            <p>Kyber decryption time: ${kyberResult.decryptionTime}ms</p>
        `);
});



const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
