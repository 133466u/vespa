package com.yahoo.security;

import java.nio.ByteBuffer;
import java.security.interfaces.XECPublicKey;
import java.util.Base64;

/**
 * A SealedSharedKey represents the public part of a secure one-way ephemeral key exchange.
 *
 * It is "sealed" in the sense that it is expected to be computationally infeasible
 * for anyone to derive the correct shared key from the sealed key without holding
 * the correct private key.
 *
 * A SealedSharedKey can be converted to--and from--an opaque string token representation.
 * This token representation is expected to be used as a convenient serialization
 * form when communicating shared keys.
 */
public record SealedSharedKey(int keyId, XECPublicKey ecdhPublicKey, byte[] tag) {

    /** Current encoding version of opaque sealed key tokens. Must be less than 256. */
    public static final int CURRENT_TOKEN_VERSION = 1;

    /** 4 byte header + 32 bytes public key + 16 bytes tag */
    private static final int BINARY_V1_TOKEN_LENGTH = 4 + 32 + 16;

    /**
     * The raw public key U coordinate represents a BigInteger in big-endian form with the
     * MSB always cleared. This means there's a 1/128 (on average) chance that all the highest
     * 8 bits of a 256-bit number are all zero (and correspondingly exponentially decreasing for
     * subsequent leading bytes). Since BigIntegers do not emit leading zero-bytes (in order to
     * enforce a singular canonical representation for any given number), we have to add this
     * padding ourselves to ensure a fixed size. The BigInteger constructors will transparently
     * remove any leading zeroes, preserving the internal canonical representation.
     */
    private static byte[] padWithLeadingZeroesIfLessThan32Bytes(byte[] buf) {
        if (buf.length == 32) {
            return buf; // Common case
        }
        if (buf.length > 32) {
            throw new IllegalStateException("Public key is more than 32 bytes in size");
        }
        byte[] padded = new byte[32];
        int padBytes = 32 - buf.length;
        for (int i = 0; i < padBytes; ++i) {
            padded[i] = 0;
        }
        for (int i = 0; i < buf.length; ++i) {
            padded[padBytes + i] = buf[i];
        }
        return padded;
    }

    /**
     * Creates an opaque URL-safe string token that contains enough information to losslessly
     * reconstruct the SealedSharedKey instance when passed verbatim to fromTokenString().
     */
    public String toTokenString() {
        if (keyId >= (1 << 24)) {
            throw new IllegalArgumentException("Key id is too large to be encoded");
        }
        byte[] pubCurveU = KeyUtils.toRawX25519PublicKeyBytes(ecdhPublicKey);
        pubCurveU        = padWithLeadingZeroesIfLessThan32Bytes(pubCurveU);

        ByteBuffer encoded = ByteBuffer.allocate(BINARY_V1_TOKEN_LENGTH);
        encoded.putInt((CURRENT_TOKEN_VERSION << 24) | keyId);
        encoded.put(pubCurveU);
        encoded.put(tag);
        encoded.flip();

        byte[] encBytes = new byte[BINARY_V1_TOKEN_LENGTH];
        encoded.get(encBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(encBytes);
    }

    /**
     * Attempts to unwrap a SealedSharedKey opaque token representation that was previously
     * created by a call to toTokenString().
     */
    public static SealedSharedKey fromTokenString(String tokenString) {
        byte[] rawTokenBytes = Base64.getUrlDecoder().decode(tokenString);
        if (rawTokenBytes.length < 4) {
            throw new IllegalArgumentException("Decoded token too small to contain a header");
        }
        ByteBuffer decoded = ByteBuffer.wrap(rawTokenBytes);
        int versionAndKeyId = decoded.getInt();
        int version = versionAndKeyId >>> 24;
        if (version != CURRENT_TOKEN_VERSION) {
            throw new IllegalArgumentException("Token had unexpected version. Expected %d, was %d"
                                               .formatted(CURRENT_TOKEN_VERSION, version));
        }
        // v1 tokens should always have a fixed length
        if (rawTokenBytes.length != BINARY_V1_TOKEN_LENGTH) {
            throw new IllegalArgumentException("Token did not have the expected size. Expected %d, was %d"
                                               .formatted(BINARY_V1_TOKEN_LENGTH, rawTokenBytes.length));
        }
        byte[] pubCurveU = new byte[32];
        decoded.get(pubCurveU);
        XECPublicKey decodedPubKey = KeyUtils.fromRawX25519PublicKey(pubCurveU);

        byte[] tag = new byte[16];
        decoded.get(tag);

        int keyId = versionAndKeyId & 0xffffff;
        return new SealedSharedKey(keyId, decodedPubKey, tag);
    }

}
