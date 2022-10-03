package com.yahoo.security;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.XECPublicKey;
import java.util.Arrays;

/**
 * Implements both the sender and receiver sides of a secure, anonymous one-way
 * ephemeral key exchange.
 *
 * A shared key, once generated, may have its sealed component sent over a public
 * channel without revealing anything about the underlying secret key. Only a
 * recipient holding the private key corresponding to the public used for shared
 * key creation may derive the same secret key as the sender.
 *
 * Note: every single shared key is unique.
 */
public class SharedKeyGenerator {

    private static final int    AES_GCM_IV_BITS       = 96; // 12 bytes
    private static final int    AES_GCM_AUTH_TAG_BITS = 128;
    private static final String AES_GCM_ALGO_SPEC     = "AES/GCM/NoPadding";

    private static final byte[] AES_KEY_CONTEXT  = "AES key".getBytes(StandardCharsets.UTF_8);
    private static final byte[] HMAC_KEY_CONTEXT = "HMAC key".getBytes(StandardCharsets.UTF_8);
    private static final byte[] EMPTY_ADDITIONAL_CONTEXT = new byte[0];

    private static byte[] computeUnkeyedSha256Digest(byte[]... buffers) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (byte[] buf : buffers) {
                digest.update(buf);
            }
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 should always be present, so this should never be reached in practice
            throw new RuntimeException(e);
        }
    }

    private static byte[] computeHmacSha256Digest(SecretKey key, byte[]... buffers) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            for (byte[] buf : buffers) {
                mac.update(buf);
            }
            return mac.doFinal();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] computeHmacTag(byte[] rawHmacKey, int tokenVersion, int keyId, byte[] additionalContext) {
        var buf = ByteBuffer.allocate(5);
        buf.put((byte)tokenVersion);
        buf.putInt(keyId);
        buf.flip();
        byte[] tagAlwaysPresentContext = new byte[buf.remaining()];
        buf.get(tagAlwaysPresentContext);

        var hmacKey = new SecretKeySpec(rawHmacKey, "HmacSHA256");
        byte[] fullTag = computeHmacSha256Digest(hmacKey, tagAlwaysPresentContext, additionalContext);
        // We truncate from the full 256-bit output to 128 bits. Still plenty secure.
        return Arrays.copyOf(fullTag, 16);
    }

    // RFC-7748 recommends checking that the shared secret is not all zero bytes.
    // Used to detect "non-contributory" private keys.
    private static void verifySharedSecretNotAllZeroes(byte[] buf) {
        // Check without introducing branch timing side channels dependent on the shared secret
        byte accu = 0;
        for (byte b : buf) {
            accu |= b;
        }
        if (accu == 0) {
            throw new IllegalArgumentException("Computed shared secret is all zeroes");
        }
    }

    private static boolean sideChannelSafeArraysEqual(byte[] lhs, byte[] rhs) {
        // Leaking the array length of the secret is fine since the _length itself_ is not secret
        if (lhs.length != rhs.length) {
            return false;
        }
        // To avoid side channel leaking caused by early exits when hitting mismatching
        // bytes, we ensure we perform no data-dependent branching as part of the comparison.
        // Only use constant time bitwise ops. `res` will be non-zero if at least one bit
        // differed in any byte compared between the two arrays.
        byte res = 0;
        for (int i = 0; i < lhs.length; ++i) {
            res |= (lhs[i] ^ rhs[i]);
        }
        return (res == 0);
    }

    private static void wipe(byte[] buf) {
        Arrays.fill(buf, (byte)0);
    }

    /**
     * It is not advisable to directly use the shared secret as the symmetric key.
     *
     * References:
     *
     *  - https://doc.libsodium.org/advanced/scalar_multiplication
     *  - https://neilmadden.blog/2016/05/20/ephemeral-elliptic-curve-diffie-hellman-key-agreement-in-java/
     *  - https://www.rfc-editor.org/rfc/rfc7748.txt
     *
     *  "Designers using these curves should be aware that for each public
     *   key, there are several publicly computable public keys that are
     *   equivalent to it, i.e., they produce the same shared secrets. Thus
     *   using a public key as an identifier and knowledge of a shared secret
     *   as proof of ownership (without including the public keys in the key
     *   derivation) might lead to subtle vulnerabilities." (RFC-7748)
     *
     * Consequently, we derive the key by a modified libsodium approach using
     * SHA-256 instead of Blake2b (same as the blogpost above, but we expect
     * explicit ordering instead of pre-sorting input).
     *
     * Let q be the computed shared secret, pk_S be the public key of the _sender_
     * and pk_R be the public key of the _receiver_, and || is the buffer
     * concatenation operator:
     *
     *   key = sha256(q || pk_S || pk_R)
     *
     * This conveniently (and unsurprisingly) has an output size of 256 bits, and
     * can thus be used directly as an AES-256 key.
     */
    private static byte[] derive256BitKey(byte[] sharedSecret,
                                          XECPublicKey ephemeralPublicKey,
                                          XECPublicKey receiverPublicKey,
                                          byte[] keyContext) {
        byte[] ephemeralCurveUCoord = ephemeralPublicKey.getU().toByteArray();
        byte[] receiverCurveUCoord  = receiverPublicKey.getU().toByteArray();
        return computeUnkeyedSha256Digest(sharedSecret, ephemeralCurveUCoord, receiverCurveUCoord, keyContext);
    }

    /**
     * We use a deterministic IV that only depends on the public keys used as part of the
     * ECDH process. This avoids having to explicitly include the IV as part of the token.
     * Since the ephemeral public key used as part of the ECDH process is only used once,
     * the resulting AES key+IV combination is also only ever used once. Consequently,
     * security is maintained.
     *
     *   IV = sha256(pk_S || pk_R)[0..11]
     *
     * Since AES-GCM IVs are 96 bits in length, we use the 12 first bytes of the SHA-256 output.
     *
     * This is functionally equivalent to libsodium's nonce/IV derivation in its "sealed box"
     * construction (again the main difference is that we use SHA-256 instead of Blake2)
     */
    private static byte[] derive96BitIV(XECPublicKey ephemeralPublicKey,
                                        XECPublicKey receiverPublicKey) {
        byte[] ephemeralCurveUCoord = ephemeralPublicKey.getU().toByteArray();
        byte[] receiverCurveUCoord  = receiverPublicKey.getU().toByteArray();
        byte[] rawShaBytes          = computeUnkeyedSha256Digest(ephemeralCurveUCoord, receiverCurveUCoord);
        return Arrays.copyOf(rawShaBytes, AES_GCM_IV_BITS / 8);
    }

    public static SecretSharedKey generateForReceiverPublicKey(XECPublicKey receiverPublicKey, int keyId) {
        try {
            var keyPairGen         = KeyPairGenerator.getInstance("X25519");
            var ephemeralKeyPair   = keyPairGen.generateKeyPair();
            var ephemeralPublicKey = (XECPublicKey) ephemeralKeyPair.getPublic();

            var keyAgreement = KeyAgreement.getInstance("XDH");
            keyAgreement.init(ephemeralKeyPair.getPrivate());
            keyAgreement.doPhase(receiverPublicKey, true);

            byte[] sharedSecret = keyAgreement.generateSecret();
            verifySharedSecretNotAllZeroes(sharedSecret);
            // Domain separation between keys used for encryption and HMAC
            byte[] derivedAesKey  = derive256BitKey(sharedSecret, ephemeralPublicKey, receiverPublicKey, AES_KEY_CONTEXT);
            byte[] derivedHmacKey = derive256BitKey(sharedSecret, ephemeralPublicKey, receiverPublicKey, HMAC_KEY_CONTEXT);

            byte[] tag          = computeHmacTag(derivedHmacKey, SealedSharedKey.CURRENT_TOKEN_VERSION, keyId, EMPTY_ADDITIONAL_CONTEXT);
            var secretKey       = new SecretKeySpec(derivedAesKey, "AES");
            var sealedSharedKey = new SealedSharedKey(keyId, ephemeralPublicKey, tag);
            return new SecretSharedKey(secretKey, sealedSharedKey);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    static SecretSharedKey fromSealedKeyInternal(SealedSharedKey sealedKey, KeyPair receiverKeyPair, boolean verifyTag) {
        try {
            var keyAgreement = KeyAgreement.getInstance("XDH");
            keyAgreement.init(receiverKeyPair.getPrivate());
            keyAgreement.doPhase(sealedKey.ecdhPublicKey(), true);

            var receiverPublicKey = (XECPublicKey) receiverKeyPair.getPublic();
            byte[] sharedSecret   = keyAgreement.generateSecret();
            verifySharedSecretNotAllZeroes(sharedSecret);
            byte[] derivedAesKey  = derive256BitKey(sharedSecret, sealedKey.ecdhPublicKey(), receiverPublicKey, AES_KEY_CONTEXT);
            byte[] derivedHmacKey = derive256BitKey(sharedSecret, sealedKey.ecdhPublicKey(), receiverPublicKey, HMAC_KEY_CONTEXT);

            byte[] tag = computeHmacTag(derivedHmacKey, SealedSharedKey.CURRENT_TOKEN_VERSION, sealedKey.keyId(), EMPTY_ADDITIONAL_CONTEXT);
            if (verifyTag && !sideChannelSafeArraysEqual(tag, sealedKey.tag())) {
                throw new IllegalArgumentException("Token integrity check failed; token is either corrupt, was " +
                                                   "generated for/with a wrong key or was generated in another context " +
                                                   "than that used for token decoding");
            }

            return new SecretSharedKey(new SecretKeySpec(derivedAesKey, "AES"), sealedKey);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static SecretSharedKey fromSealedKey(SealedSharedKey sealedKey, KeyPair receiverKeyPair) {
        return fromSealedKeyInternal(sealedKey, receiverKeyPair, true);
    }

    // TODO probably move these away?
    private static Cipher makeAes256GcmCipher(SecretSharedKey secretSharedKey,
                                              XECPublicKey receiverPublicKey,
                                              int cipherMode) {
        try {
            var cipher  = Cipher.getInstance(AES_GCM_ALGO_SPEC);
            byte[] iv   = derive96BitIV(secretSharedKey.sealedSharedKey().ecdhPublicKey(), receiverPublicKey);
            var gcmSpec = new GCMParameterSpec(AES_GCM_AUTH_TAG_BITS, iv);
            cipher.init(cipherMode, secretSharedKey.secretKey(), gcmSpec);
            return cipher;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    public static Cipher makeAes256GcmEncryptionCipher(SecretSharedKey secretSharedKey,
                                                       XECPublicKey receiverPublicKey) {
        return makeAes256GcmCipher(secretSharedKey, receiverPublicKey, Cipher.ENCRYPT_MODE);
    }

    public static Cipher makeAes256GcmDecryptionCipher(SecretSharedKey secretSharedKey,
                                                       XECPublicKey receiverPublicKey) {
        return makeAes256GcmCipher(secretSharedKey, receiverPublicKey, Cipher.DECRYPT_MODE);
    }

}
