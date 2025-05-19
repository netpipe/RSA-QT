#include <iostream>
#include <string>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/pssr.h>
#include <cryptopp/oaep.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>

using namespace CryptoPP;
using namespace std;

int main() {
    AutoSeededRandomPool rng;

    // Generate RSA-2048 keypair
    InvertibleRSAFunction privateParams;
    privateParams.Initialize(rng, 2048);
    RSA::PrivateKey privateKey(privateParams);
    RSA::PublicKey publicKey(privateParams);

    // 1. Generate a random AES-256 key
    SecByteBlock aesKey(AES::DEFAULT_KEYLENGTH * 2); // 32 bytes
    rng.GenerateBlock(aesKey, aesKey.size());

    // 2. Encrypt AES key with RSA public key
    std::string encryptedAesKey;
    RSAES_OAEP_SHA_Encryptor rsaEncryptor(publicKey);
    StringSource ss1(aesKey, aesKey.size(), true,
        new PK_EncryptorFilter(rng, rsaEncryptor,
            new StringSink(encryptedAesKey)
        )
    );

    // 3. Encrypt a message using AES-256-CBC
    byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(iv, sizeof(iv));

    std::string plaintext = "This is a secret message.";
    std::string ciphertext;

    CBC_Mode<AES>::Encryption aesEncryptor;
    aesEncryptor.SetKeyWithIV(aesKey, aesKey.size(), iv);

    StringSource ss2(plaintext, true,
        new StreamTransformationFilter(aesEncryptor,
            new StringSink(ciphertext)
        )
    );

    // Simulate sending encrypted AES key, IV, ciphertext
    std::string decrypted;
    std::string decryptedAesKey;
    CBC_Mode<AES>::Decryption aesDecryptor;

    // 4. Decrypt AES key with RSA private key
    RSAES_OAEP_SHA_Decryptor rsaDecryptor(privateKey);
    StringSource ss3(encryptedAesKey, true,
        new PK_DecryptorFilter(rng, rsaDecryptor,
            new StringSink(decryptedAesKey)
        )
    );

    // 5. Decrypt the message with AES-256-CBC
    aesDecryptor.SetKeyWithIV((const byte*)decryptedAesKey.data(), decryptedAesKey.size(), iv);
    StringSource ss4(ciphertext, true,
        new StreamTransformationFilter(aesDecryptor,
            new StringSink(decrypted)
        )
    );

    // Output
    cout << "Original:  " << plaintext << endl;
    cout << "Decrypted: " << decrypted << endl;

    return 0;
}
