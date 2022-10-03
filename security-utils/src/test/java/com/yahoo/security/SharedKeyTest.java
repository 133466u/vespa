package com.yahoo.security;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class SharedKeyTest {

    static XECPublicKey xecPublicKey(KeyPair kp) {
        return (XECPublicKey)kp.getPublic();
    }

    @Test
    void generated_secret_key_is_256_bit_aes() {
        var receiverKeyPair = KeyUtils.generateX25519KeyPair();
        var shared = SharedKeyGenerator.generateForReceiverPublicKey(xecPublicKey(receiverKeyPair), 1);
        var secret = shared.secretKey();
        assertEquals(secret.getAlgorithm(), "AES");
        assertEquals(secret.getEncoded().length, 32);
    }

    @Test
    void sealed_shared_key_can_be_exchanged_via_token_and_computes_identical_secret_key_at_receiver() {
        var receiverKeyPair = KeyUtils.generateX25519KeyPair();

        var myShared    = SharedKeyGenerator.generateForReceiverPublicKey(xecPublicKey(receiverKeyPair), 1);
        var publicToken = myShared.sealedSharedKey().toTokenString();

        var theirSealed = SealedSharedKey.fromTokenString(publicToken);
        var theirShared = SharedKeyGenerator.fromSealedKey(theirSealed, receiverKeyPair);

        System.out.format("My secret key:\n%s\n\n",    Hex.toHexString(myShared.secretKey().getEncoded()));
        System.out.format("Shared token:\n%s\n\n",     publicToken);
        System.out.format("Their secret key:\n%s\n\n", Hex.toHexString(theirShared.secretKey().getEncoded()));

        assertArrayEquals(myShared.secretKey().getEncoded(), theirShared.secretKey().getEncoded());
    }

    @Test
    void token_v1_representation_is_stable() {
        var receiverPrivate = KeyUtils.fromBase64EncodedX25519PrivateKey("KgP9wE3oHuHzkaytMG7sv8I6IrRWgVA2ARBhi6gpJM8");
        var receiverPublic  = KeyUtils.fromBase64EncodedX25519PublicKey("fwWHcSuKft1UYHJmekuReY2RFvpjML3lakql92dXtHM");
        var receiverKeyPair = new KeyPair(receiverPublic, receiverPrivate);

        // Token generated for the above receiver public key, with the below expected shared secret (in hex)
        var publicToken = "AQAAARJDVUVcRoXoVxHn8UKw4RfQie3ODCNg6C6wYnsfz5MkFQu6yyX_v0Lu9VDtqWBKgw";
        var expectedSharedSecret = "33f2b513af25a1ba1506275340cfe3432656fcc6b9f007a9607eaca37d83ffba";

        var theirSealed = SealedSharedKey.fromTokenString(publicToken);
        var theirShared = SharedKeyGenerator.fromSealedKey(theirSealed, receiverKeyPair);

        assertEquals(expectedSharedSecret, Hex.toHexString(theirShared.secretKey().getEncoded()));
    }

    @Test
    void unrelated_private_key_can_not_compute_correct_secret_key() {
        // Bob wants to send a secret key to Alice via a sealed token.
        // Eve is sneaking in the bushes, reads the token and tries to decrypt with her own private key.
        // Naturally, this should not yield the correct key.
        var aliceKeyPair = KeyUtils.generateX25519KeyPair();
        var bobShared    = SharedKeyGenerator.generateForReceiverPublicKey(xecPublicKey(aliceKeyPair), 1);
        var bobSecretKey = bobShared.secretKey();
        // Eve reuses the public key of Alice, but since she does not have the private key she wings
        // it and generates an entirely unrelated private key.
        // Note: this will fail if KeyPair ever adds checking that the keys are related.
        var eveKeyPair = new KeyPair(aliceKeyPair.getPublic(), KeyUtils.generateX25519KeyPair().getPrivate());
        // Secret key computations are just EC point multiplications, so there is no inherent
        // detection of bad keys. But the computed secret key shall never match the actual secret key.
        // Note: normally this would trigger a failure due to tag verification failure; the tag
        // will not be correct unless the shared secret matches. To test this case we use a
        // protected internal method that allows for explicitly disabling the tag check.
        // Don't do this at home!
        var eveShared = SharedKeyGenerator.fromSealedKeyInternal(bobShared.sealedSharedKey(), eveKeyPair, false);
        assertFalse(Arrays.equals(bobSecretKey.getEncoded(), eveShared.secretKey().getEncoded()));

        System.out.format("Bob's secret key:\n%s\n\n", Hex.toHexString(bobShared.secretKey().getEncoded()));
        System.out.format("Eve's secret key:\n%s\n\n", Hex.toHexString(eveShared.secretKey().getEncoded()));
    }

    // Slightly different scenario from the above; Eve is a legitimate potential token recipient who
    // tries to decode a token that was created for Alice's public key instead of her own. Tag verification
    // ensures that this is detected when the key is unsealed. This is a much better user experience than
    // only discovering it after using a bogus key to decrypt 100 gigs of data, only failing at the AES GCM
    // auth tag check at the end.
    @Test
    void unrelated_private_key_is_detected_by_tag_mismatch() {
        var aliceKeyPair = KeyUtils.generateX25519KeyPair();
        var eveKeyPair   = KeyUtils.generateX25519KeyPair();
        var bobShared    = SharedKeyGenerator.generateForReceiverPublicKey(xecPublicKey(aliceKeyPair), 1);
        assertThrows(IllegalArgumentException.class, // TODO consider distinct exception class
                     () -> SharedKeyGenerator.fromSealedKey(bobShared.sealedSharedKey(), eveKeyPair));
    }

    @Test
    void token_carries_key_id_as_metadata() {
        int keyId       = 12345;
        var keyPair     = KeyUtils.generateX25519KeyPair();
        var myShared    = SharedKeyGenerator.generateForReceiverPublicKey(xecPublicKey(keyPair), keyId);
        var publicToken = myShared.sealedSharedKey().toTokenString();
        var theirShared = SealedSharedKey.fromTokenString(publicToken);
        assertEquals(theirShared.keyId(), keyId);
    }

    @Test
    void token_public_key_is_leading_zero_padded_to_32_bytes() {
        // Unlikely, but possible; only 29 bytes of data, i.e. 3 implicit leading bytes are all zero.
        byte[] pubKeyUBytes = Hex.decode("2da6548b1a99636e37a82e19df1a1f79268e48143a6812c431e216d718");
        var pk = KeyUtils.fromRawX25519PublicKey(pubKeyUBytes);
        assertArrayEquals(pk.getU().toByteArray(), pubKeyUBytes);
        var token = new SealedSharedKey(12345, pk, new byte[16]);
        // Without padding, this will fail since we explicitly check the token length.
        var decodedToken = SealedSharedKey.fromTokenString(token.toTokenString());
        assertArrayEquals(decodedToken.ecdhPublicKey().getU().toByteArray(), pubKeyUBytes);
    }

    static byte[] streamEncryptString(String data,
                                      SecretSharedKey secretSharedKey,
                                      XECPublicKey receiverPublicKey) throws IOException {
        var cipher = SharedKeyGenerator.makeAes256GcmEncryptionCipher(secretSharedKey, receiverPublicKey);
        var outStream = new ByteArrayOutputStream();
        try (var cipherStream = new CipherOutputStream(outStream, cipher)) {
            cipherStream.write(data.getBytes(StandardCharsets.UTF_8));
            cipherStream.flush();
        }
        return outStream.toByteArray();
    }

    static String streamDecryptString(byte[] encrypted,
                                      SecretSharedKey secretSharedKey,
                                      XECPublicKey receiverPublicKey) throws IOException {
        var cipher   = SharedKeyGenerator.makeAes256GcmDecryptionCipher(secretSharedKey, receiverPublicKey);
        var inStream = new ByteArrayInputStream(encrypted);
        var total    = ByteBuffer.allocate(encrypted.length); // Assume decrypted form can't be _longer_
        byte[] tmp   = new byte[8]; // short buf to test chunking
        try (var cipherStream = new CipherInputStream(inStream, cipher)) {
            while (true) {
                int read = cipherStream.read(tmp);
                if (read == -1) {
                    break;
                }
                total.put(tmp, 0, read);
            }
        }
        total.flip();
        byte[] strBytes = new byte[total.remaining()];
        total.get(strBytes);
        return new String(strBytes, StandardCharsets.UTF_8);
    }

    @Test
    void can_create_symmetric_ciphers_from_shared_secret_key_and_public_keys() throws Exception {
        var receiverKeyPair = KeyUtils.generateX25519KeyPair();
        var receiverPubKey  = xecPublicKey(receiverKeyPair);
        var myShared        = SharedKeyGenerator.generateForReceiverPublicKey(receiverPubKey, 1);

        String terrifyingSecret = "birds are not real D:";
        byte[] encrypted = streamEncryptString(terrifyingSecret, myShared, receiverPubKey);
        String decrypted = streamDecryptString(encrypted, myShared, receiverPubKey);
        assertEquals(terrifyingSecret, decrypted);
    }

}
