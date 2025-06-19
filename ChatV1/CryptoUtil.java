package ChatV1;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Provides cryptographic utilities for the chat application
 * Implements a hybrid cryptosystem with AES for symmetric encryption
 * and RSA for asymmetric encryption
 */
public class CryptoUtil {
    // RSA key sizes
    private static final int RSA_KEY_SIZE = 2048;
    
    // AES key sizes
    private static final int AES_KEY_SIZE = 256;
    
    // Initialization Vector size
    private static final int IV_SIZE = 16;

    /**
     * Generate an RSA key pair
     * @return KeyPair containing public and private keys
     */
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(RSA_KEY_SIZE);
        return keyGen.generateKeyPair();
    }
    
    /**
     * Generate an AES secret key
     * @return SecretKey for AES encryption
     */
    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE);
        return keyGen.generateKey();
    }
    
    /**
     * Generate a random initialization vector
     * @return IvParameterSpec for AES encryption
     */
    public static IvParameterSpec generateIV() {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
    
    /**
     * Encrypt data using RSA public key
     * @param data The data to encrypt
     * @param publicKey The RSA public key
     * @return Base64 encoded encrypted data
     */
    public static String encryptRSA(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(data);
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
    
    /**
     * Decrypt data using RSA private key
     * @param encryptedData Base64 encoded encrypted data
     * @param privateKey The RSA private key
     * @return Decrypted data
     */
    public static byte[] decryptRSA(String encryptedData, PrivateKey privateKey) throws Exception {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedBytes);
    }
    
    /**
     * Encrypt data using AES secret key
     * @param data The data to encrypt
     * @param key The AES secret key
     * @param iv The initialization vector
     * @return Base64 encoded encrypted data
     */
    public static String encryptAES(String data, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        
        // Combine IV and encrypted data
        byte[] combined = new byte[iv.getIV().length + encryptedBytes.length];
        System.arraycopy(iv.getIV(), 0, combined, 0, iv.getIV().length);
        System.arraycopy(encryptedBytes, 0, combined, iv.getIV().length, encryptedBytes.length);
        
        return Base64.getEncoder().encodeToString(combined);
    }
    
    /**
     * Decrypt data using AES secret key
     * @param encryptedData Base64 encoded encrypted data (includes IV)
     * @param key The AES secret key
     * @return Decrypted data
     */
    public static String decryptAES(String encryptedData, SecretKey key) throws Exception {
        byte[] combined = Base64.getDecoder().decode(encryptedData);
        
        // Extract IV
        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(combined, 0, iv, 0, iv.length);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        // Extract encrypted data
        byte[] encryptedBytes = new byte[combined.length - iv.length];
        System.arraycopy(combined, iv.length, encryptedBytes, 0, encryptedBytes.length);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        
        return new String(decryptedBytes);
    }
    
    /**
     * Sign data using RSA private key
     * @param data The data to sign
     * @param privateKey The RSA private key
     * @return Base64 encoded signature
     */
    public static String sign(String data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data.getBytes());
        return Base64.getEncoder().encodeToString(signature.sign());
    }
    
    /**
     * Verify signature using RSA public key
     * @param data The data that was signed
     * @param signature Base64 encoded signature
     * @param publicKey The RSA public key
     * @return true if signature is valid, false otherwise
     */
    public static boolean verify(String data, String signature, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(data.getBytes());
        return sig.verify(Base64.getDecoder().decode(signature));
    }
    
    /**
     * Convert a SecretKey to a Base64 encoded string
     */
    public static String secretKeyToString(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }
    
    /**
     * Convert a Base64 encoded string to a SecretKey
     */
    public static SecretKey stringToSecretKey(String keyStr) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(keyStr);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }
    
    /**
     * Convert a PublicKey to a Base64 encoded string
     */
    public static String publicKeyToString(PublicKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }
    
    /**
     * Convert a Base64 encoded string to a PublicKey
     */
    public static PublicKey stringToPublicKey(String keyStr) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(keyStr);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
    
    /**
     * Convert a PrivateKey to a Base64 encoded string
     */
    public static String privateKeyToString(PrivateKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }
    
    /**
     * Convert a Base64 encoded string to a PrivateKey
     */
    public static PrivateKey stringToPrivateKey(String keyStr) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(keyStr);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }
    
    /**
     * Create an initialization vector from bytes
     */
    public static IvParameterSpec createIvFromBytes(byte[] iv) {
        return new IvParameterSpec(iv);
    }
}
