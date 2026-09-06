// Fixture: Java JCA usage, including a transformation string that has to be
// split into algorithm, mode and padding.
package gov.example;

import javax.crypto.Cipher;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.KeyPairGenerator;

public class Crypto {

    public Cipher modern() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    public Cipher legacy() throws Exception {
        // 56-bit key, exhaustively searchable.
        return Cipher.getInstance("DES/CBC/PKCS5Padding");
    }

    public MessageDigest digest() throws Exception {
        return MessageDigest.getInstance("SHA-256");
    }

    public Signature signer() throws Exception {
        return Signature.getInstance("SHA256withRSA");
    }

    public KeyPairGenerator keys() throws Exception {
        return KeyPairGenerator.getInstance("RSA");
    }
}
