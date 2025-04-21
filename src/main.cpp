#include <iostream>
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/ecp.h>
#include <cryptopp/oids.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/des.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/secblock.h>
#include <cctype>

using namespace CryptoPP;
using namespace std;

// Helper function to keep only letters and digits
string sanitizeAlphaNum(const string &input)
{
    string output;
    for (char c : input)
    {
        if (isalpha(c) || isdigit(c))
        {
            output += c;
        }
        else if (isalpha(c))
        {
            output += c;
        }
    }
    return output;
}

// Helper to convert hash hex to numeric-only form
string hashToNumericOnly(const string &hex)
{
    string numeric;
    for (char c : hex)
    {
        if (isdigit(c))
        {
            numeric += c;
        }
        else
        {
            // Map A-F to 1-6 to keep only digits
            numeric += to_string((toupper(c) - 'A' + 1));
        }
    }
    return numeric;
}

int main()
{
    AutoSeededRandomPool prng;

    // User input
    string plain;
    cout << "Enter your message: ";
    getline(cin, plain);

    // Generate ECC key pair
    ECDSA<ECP, SHA256>::PrivateKey senderPriv;
    senderPriv.Initialize(prng, ASN1::secp256r1());
    ECDSA<ECP, SHA256>::PublicKey senderPub;
    senderPriv.MakePublicKey(senderPub);

    // Generate DES key
    SecByteBlock desKey(DES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(desKey, desKey.size());

    // Encrypt message using DES
    string cipher;
    CryptoPP::byte iv[DES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    CBC_Mode<DES>::Encryption desEncryptor;
    desEncryptor.SetKeyWithIV(desKey, desKey.size(), iv);
    StringSource(plain, true,
                 new StreamTransformationFilter(desEncryptor,
                                                new StringSink(cipher)));

    // Sign the encrypted message
    string signature;
    ECDSA<ECP, SHA256>::Signer signer(senderPriv);
    StringSource(cipher, true,
                 new SignerFilter(prng, signer, new StringSink(signature)));

    // Compute SHA-256 hash of cipher
    string digest;
    SHA256 hash;
    StringSource(cipher, true,
                 new HashFilter(hash, new HexEncoder(new StringSink(digest))));

    // Sanitize outputs
    string sanitizedCipher = sanitizeAlphaNum(cipher);
    string sanitizedSignature = sanitizeAlphaNum(signature);
    string numericHash = hashToNumericOnly(digest);

    cout << "\n--- Output ---\n";
    cout << "Encrypted Message: " << sanitizedCipher << endl;
    cout << "Digital Signature: " << sanitizedSignature << endl;
    cout << "SHA-256 Hash (Digits Only): " << numericHash << endl;

    return 0;
}
