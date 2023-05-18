const express = require('express');
const app = express();
const { rsaAnalysis, mcelieceAnalysis, kyberAnalysis } = require('./results');

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
        <table>
            <tr>
                <th>Parameters</th>
                <th>RSA</th>
                <th>McEliece</th>
                <th>Kyber</th>
            </tr>
            <tr>
                <th>Decrypted message</th>
                <td>${rsaResult.aes_decrypted}</td>
                <td>${mcelieceResult.aesDecrypted}</td>
                <td>${kyberResult.decrypted}</td>
            </tr>
            <tr>
                <th>KeyGen time</th>
                <td>${rsaResult.rsaRanTime} ms</td>
                <td>${mcelieceResult.keygenTime} ms</td>
                <td>${kyberResult.keygenTime} ms</td>
            </tr>
            <tr>
                <th>Encryption time</th>
                <td>${rsaResult.rsaEncTime} ms</td>
                <td>${mcelieceResult.encryptionTime} ms</td>
                <td>${kyberResult.encryptionTime} ms</td>
            </tr>
            <tr>
                <th>Decryption time</th>
                <td>${rsaResult.rsaDecTime} ms</td>
                <td>${mcelieceResult.decryptionTime} ms</td>
                <td>${kyberResult.decryptionTime} ms</td>
            </tr>
            <tr>
                <th>Memory consumed</th>
                <td>${rsaResult.memoryConsumed} bytes</td>
                <td>${mcelieceResult.memoryConsumed} bytes</td>
                <td>${kyberResult.memoryConsumed} bytes</td>
            </tr>
        </table>
    `);

});

const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
