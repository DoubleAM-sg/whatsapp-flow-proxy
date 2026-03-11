import crypto from 'crypto';

// --- YOUR NEW PRIVATE KEY ---
const PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAuLGXqdBioSVw/0YcyRSU87t7lPuec8bLFbEFBMvKPTFkBEjZ
N2BblgRGoVd96/e4aCq9F4nYDUowJRTkysBDUw0+a+hSscvYVE/8CJPxeo3DQ/zG
elH5kRRTVs3uTK3yH7Gwwv+r0lBM8s39wepCjXrFgmlF4uf25LjAOgtRx1PIQCpp
mDpb4Cos74ImQzw39IoUrTd0rvWH3n+yhQu+TDKqIwT6l5sn3ZxqfYGkYPXRJc0k
4q9gd8JJ2Wjy1tp76ybesyEc5I86UYnnCUesxgPTOI8Yh0pmabOtbyQdl7kOFo6P
8NkohWxgCnei8mMhUMqV9y/m0tGE7QLfrbI7HQIDAQABAoIBAFrrYePAp6z4h4XC
+Aysyx6o3o9axofsBrFo8TWJNMem9rt9OSEfmDZjaHmoXl65FdiBoZBi1S7FpKm8
fVyqBPpvfJkWRw8rcBUhQsreOXPBMazYVMSGcjrPLK+AtJyezKB5krCLuAPSb+7f
JNo+/gAzveMS+8pVsp6prEdmpx1d9QKIgLC691Pmdw2C1wnOdyVUZXq8/8ps/U7o
qhpxQ1+GjpZTIRW1gVTmvcY+UpnY9k7yNa0FfIgDY5w4Opkf2lCXfIjLTiOrQJ38
pVV000LgCMyuRtc/BFix2MIp9aLGH/Z4fbXtQLC9qoHPdhAMKcGQiIFy4ed9KlzL
veGPvikCgYEA3r2pCk6AhSz03yyEuBwanQt3UzIyOVIcXo0mZhzRhhDDfwRwXoeM
kpaoURAUR1xnB09h0YSyEpWlyyCl5/FPgyLGJIQvAFvuJGUxdbeSzO/ScmK6XXce
fYgA13Xn5vAUwY98mvRNPPV2r8PAeQDcv7n8XVLidqTHWCtT01qJxocCgYEA1EWR
dGrJN1+jWub77yO9MAsF4PUvNDnI/e4Iv/bTMVKKp4y0g1y8htD5kbLn03BZx/tD
8nRrpv9kZ7625T37r3myFYuMgP/ViK+JiL4ZCl7vWHNA45VOfmli1tSZ9aUvD5kD
/WkCxCQiu9mDih60iGzf4lMduNiOGpXt31KnNjsCgYBxX7xBAMAuCToCtpg/Vh69
vO5ZrH0f7AmAnvvikdycDsBTUKEZnIkSvBikWjjYMdJHSEKT8KTrDLy87btEmfFM
4FBWmemKl0BZyiAouO3B3ngRvOr7U/xzDNzQzrThOWZ3N1/HR35g/tgQkuTPMn8q
H7KyldOrbCgDWtpqA/WI1QKBgG8XAWqFwEyEdr9KBys97vLHsgnrBwsz+qY5/sZH
7HrxkbLiBk6BKAD+OL4xfPXA5JuuOf8XQoehPPC2dI1AhQlujO6Nm7ifKydfhoDT
y9MLoAMQPjNcnjm1+Y4osXJHQnvNPrNOU65Gow7gZODR9PU41WpiyTlFzAjJ0jV/
0halAoGBAM04TEDdlVu/UXPlSc5b9bSKAJunUqUBRogXTroz/t5xgtidt8OSpUka
82zrDcWf7khRtvTRgTFIAhZ9RpxmzNwOT4wdYnY0ydS4U2ErQnQUMcBX4R+14Zqj
NUN6aHdljcUkFL2EEj6KjkjKCENiRfHfLr/vfeYYWe6aK13k7Ick
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
