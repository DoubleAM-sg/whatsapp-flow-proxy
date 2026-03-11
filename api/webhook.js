import crypto from 'crypto';

// --- YOUR NEW PRIVATE KEY ---
const PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQB/bBTQAd4eQCe7heeyHusV7247Q60xMwCoVJaIAGgROHa1ELVr
jCrEktO651vpst9d98eE0EjSUfazJ8d2+ryf3ZZfRj+KEH69cWIs8+2DwacxSlqr
Zcma/5z0iGEdbT0rK/u23f4OZEj/McepjlxY5817X57O+n85I3vPfP2gynIGM4Gw
o5FjLnFBP1wGUPyg3531tCiaRS1CWb0QcWX3DXzm7ib1P8f8rm2AOcmFW4dHTieX
pXKS9bPyjPVb3JzTAZnUjCBpMMq0cG4DybDp2d38c7AniY/GyWAWRUF9JfRitCC5
7YWAMTWEYeiYQs74cYlgynNh0miA+mmW9hR9AgMBAAECggEAce5LtajV16p5XDxg
bG0kuZo5r5fVdZYq0le/uJ7UbgFUcpUcAat0WgsGcamIDy82dSilJuWtFxDeSlYZ
DRMoMLDKUSnYijQxfmWw6Iy6JAK04WegJnx+hK5kwmhmnQ8dkEplaJ6ZGHkmo7b4
1WxKuduZaOSYdGyZ8Jb/jwgtJuRZVFHjwNQdxefYq8nQq0qLQL3evTo9NVySJZT6
1UzbNJIxiQn/wjiO6C+fW8ZXZaKj1XOFCxUNUnV0b3rKq5yl8gDA0/2G9uJm6wIq
CzC2mwpT/dJIOnVMlz5OPgnlyU9nCj1FyrwjA+K3djt0fM4gakcbXGgr/y+qUbRd
iKfWgQKBgQC7pqB64i4TTIt6/HrxDA450qY9p8hs6QFeNVG/cdUUe0KYhWKZIg2U
ctSeIoKSH/m5vZJz8H171h8gIlte3IuJm17dPDjCIY2dWXRo6p/dLGefe7YTRcHl
n8KbmPvxp/aMToTBRWQN1Cp/5pFVOhKY9Y8Gyv/d9jqYk6txnhCV7QKBgQCt1XkK
e1kyqFGNW+tk1I2c3Jnkk5ta4ff6ahkfhRS8foVyLTEreYfOcT5jrdTFLfW9ZAZl
gItwQI+0IRJFo4TmLDQ4nt5Vg6qzdgxqZRs+v89fZiADqqp1mBF7YZi8ihlBZkXC
Gf/TpI6Loyq1Y/7+/U26wri7L8KVnZxZ7ISm0QKBgEB2w5azcMSsfRYo+ksoqxJu
LTHtG8teWFv20TiFcH/ywDQJTo/wxN2EfUo97MEqPu3yFAfETDdonZS6eM0j0sPZ
HkO+VnlKcY3mlzkbsQOYJ5kANNJ2GmA5++7cJWElJGua5bxHjFG720XI/ZBbvNvT
L+lTf4bO+d5EjJchh+0ZAoGBAJgZg/ou6WIQsqKsPfAQpwQMZb8BhFpmA7MhKHBS
4kz3q022yyIOCU0R+xP+ooAQ8cbQAWTIr7j9VH+4vCMgq4U2Qk8Uetd6CF9UOBLT
+p3R+OGxGuv6ZYHVF97MC3dUojp+ASWP2C9X+b2mfBUQtKpp+pwiCr8GUAzXRlnM
QFkxAoGBAIZwBbJJSS4LLWNMBtMhTGBpelM7gforqwKNtaFmPD8TQnD+mIJoDOKl
whoJlGAYb4GLZ/4HqiEqFoK0YgKAnVUSU0e6i+Tkmh9Idmoq4TK2M+YhhDxeMpKs
hEinyIL64q0EffChc3kY7nFY1fnxVrKs7opwNmkQMhHGbQvyEqH3
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
