import crypto from 'crypto';

// --- YOUR NEW PRIVATE KEY ---
const PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEoQIBAAKCAQB0zH1EqKDC2dT8AtK7N7W8jJFX6FP+ixgRbgW040LI8vd7wMPJ
xXYY+FDU4FLBzHyi+91idHmmqdmBCKNdr/YCc9aOmpXP6toDfdsbCPlwhdQNQwBi
G2zV7OLdoB0zkr1mduVxST98tbZJCPa9axc2mslpvU79D5vYivXyclXiUsqb8nmG
pcgOxrcT/0KYVOKM7cCoucOTuhUDgO8pZ5ton12uLcpDUEZlHrWdzwy+tSnN3pof
n3nMudqfIqUDqMyAfPfGvZ3+Gvm0RIG69QpDiUqmhYopooCicW9J1FtrBmMrZ6d/
M4fJL/PF3rVaU3tyAHoAHdi12Rb+QH/ZJuYlAgMBAAECggEAY5qzxWaM2j5MDLIX
pgMHYAj8NdxyLOPPnaWXBkC8hoP1G7sy/JIBeZ/hxviaepz5OUDS9hBgYgn867ZD
IzVY9ZR1x9z6n3one8zLmo2XsybdxIV8AS5kLTc77UaLQJ0GGiiQ2IBfvOl1z2ju
inCWNkHgO+VuRA8Yl51BywVISp2rHffqqY5I+boIJ9vKJ1RTFrue5qVhHbdBXEmb
Y0KJ6U+P1yGJXHnXswDybE0iN+cKHbkKSU4ddl1gn9dLwZ/fvQpz9pFiB5cPBPAh
7aeLizKbHzN6meLLAszFxTwU1GG8s8NMF1i9kI18B0SQKqjlCAQ6la+XOv+lEauS
td/jIQKBgQCwtg70vdtdxa55xxN8MNuGXhmdOvscWa/aToGnVt2I/m6G0RCoqVZN
G0+6sNPwZIwzewgFBQX58XluPh4NoCplaI59V7ur6RhPvTHYBmqamLSIgZS0gSV8
PT+hgLR9vLO2RWt0biXcu16wODgxzWcFRdNQkR/OCzCo2A5IdhYfLQKBgQCpNJdD
mytIBMkZFTjmzAhHeDgJTzW0z+O61JuAESxtYA54l/zU84GR20hQ3TLRBovWQtjR
U6u/zqtzmMuOhWoDYXwGbEounRVJFTPp1oDIvuEYx+mX/mKCn0kZAuPTCKJcsiui
yW3DV9MQ4VtEk56+3G23fmsvtzWHJe6f6FP92QKBgH2dfXY2vAilrIh+nnhK1tJm
c/jT44tcqegapInK8wIeM318gkYS0flP79Y7Ov2IzC0QSTwgPQZWxEY8u+pdr6WU
tK2fPxZORWzxhcwVi5RH9xWOX6IMqBPwChqJPkSfbnSkVmVWo22MeBv2auPkKlaS
M0vzTdOPGtD7fPO/lawlAoGAEskP8iWMDJbbbLl6c8U7NhQWxJHSuJxMADYSfYlq
kUoU0Tauj0XpoLPjt3aXabV8WPFa+QJ9EvJy/oZ8MvqE5pMwHdZv9fTipBaCiPeT
nLX0b7fiK0nGzhG5H9m+SXOv8vKk/ZG3afSaLkmWxGpPOYlndPPIGqgQfUyszXwR
tyECgYB1MwnvrLsOsR90fCtVfP3DBTC5p84STIk6DhVQXhP7Ii1tR+/oS/Y8STp3
if+GqBDkLMJDDdfQwsaXCytQutRynpWq12R4qXuTlzv48uFOLu3sAjLWTitCfHaN
gz1pfyHXgC13/WhorxTeAv3IghC2uf+ZV4Ws2sT4dBvMNN26UA==
-----END RSA PRIVATE KEY-----`;

export default async function handler(req, res) {
    // Only accept POST requests from Meta
    if (req.method !== 'POST') {
        return res.status(405).send('Method Not Allowed');
    }

    try {
        const { encrypted_flow_data, encrypted_aes_key, initial_vector } = req.body;

        if (!encrypted_flow_data || !encrypted_aes_key || !initial_vector) {
            return res.status(400).send("Missing encrypted payloads");
        }

        // 1. Decrypt the AES Key using RSA
        const decryptedAesKey = crypto.privateDecrypt(
            {
                key: PRIVATE_KEY,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256',
            },
            Buffer.from(encrypted_aes_key, 'base64')
        );

        // 2. Decrypt the Flow Data using AES-GCM
        const iv = Buffer.from(initial_vector, 'base64');
        const flowDataBuffer = Buffer.from(encrypted_flow_data, 'base64');
        
        // Split the auth tag (last 16 bytes) from the ciphertext
        const authTag = flowDataBuffer.subarray(-16);
        const ciphertext = flowDataBuffer.subarray(0, -16);

        const decipher = crypto.createDecipheriv('aes-128-gcm', decryptedAesKey, iv);
        decipher.setAuthTag(authTag);
        
        let decryptedJSON = decipher.update(ciphertext, 'binary', 'utf8') + decipher.final('utf8');
        const parsedData = JSON.parse(decryptedJSON);

        // 3. Handle Meta's Health Check (Ping)
        if (parsedData.action === 'ping') {
            const pong = JSON.stringify({ version: "3.0", data: { status: "active" } });
            
            const cipher = crypto.createCipheriv('aes-128-gcm', decryptedAesKey, iv);
            let encryptedPong = cipher.update(pong, 'utf8', 'base64') + cipher.final('base64');
            const pongTag = cipher.getAuthTag().toString('base64');
            
            // Send the Base64 string directly back to Meta
            return res.status(200).send(encryptedPong + pongTag);
        }

        // 4. (Later) Forward real user submissions to Make.com or GHL here!
        return res.status(200).send('Success');

    } catch (err) {
        console.error("Decryption Error:", err);
        return res.status(500).send(`Decryption failed: ${err.message}`);
    }
}
