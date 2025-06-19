package Chat.crypto;

import Chat.common.Config;
import Chat.common.exceptions.CryptoException;

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
    /**
     * Generate an RSA key pair
     * @return KeyPair containing public and private keys
     * @throws CryptoException if key generation fails
     */
    public static KeyPair generateRSAKeyPair() throws CryptoException {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(Config.RSA_ALGORITHM);
            keyGen.initialize(Config.RSA_KEY_SIZE);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Failed to generate RSA key pair", e);
        }
    }
    
    /**
     * Generate an AES secret key
     * @return SecretKey for AES encryption
     * @throws CryptoException if key generation fails
     */
    public static SecretKey generateAESKey() throws CryptoException {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(Config.AES_ALGORITHM);
            keyGen.init(Config.AES_KEY_SIZE);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Failed to generate AES key", e);
        }
    }
    
    /**
     * Generate a random initialization vector
     * @return IvParameterSpec for AES encryption
     */
    public static IvParameterSpec generateIV() {
        byte[] iv = new byte[Config.IV_SIZE];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
    
    /**
     * Encrypt data using RSA public key
     * @param data The data to encrypt
     * @param publicKey The RSA public key
     * @return Base64 encoded encrypted data
     * @throws CryptoException if encryption fails
     */
    public static String encryptRSA(byte[] data, PublicKey publicKey) throws CryptoException {
        try {
            Cipher cipher = Cipher.getInstance(Config.RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(data);
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new CryptoException("Failed to encrypt data with RSA", e);
        }
    }
    
    /**
     * Decrypt data using RSA private key
     * @param encryptedData Base64 encoded encrypted data
     * @param privateKey The RSA private key
     * @return Decrypted data
     * @throws CryptoException if decryption fails
     */
    public static byte[] decryptRSA(String encryptedData, PrivateKey privateKey) throws CryptoException {
        try {
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
            Cipher cipher = Cipher.getInstance(Config.RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(encryptedBytes);
        } catch (Exception e) {
            throw new CryptoException("Failed to decrypt data with RSA", e);
        }
    }
    
    /**
     * Encrypt data using AES secret key
     * @param data The data to encrypt
     * @param key The AES secret key
     * @param iv The initialization vector
     * @return Base64 encoded encrypted data (includes IV)
     * @throws CryptoException if encryption fails
     */
    public static String encryptAES(String data, SecretKey key, IvParameterSpec iv) throws CryptoException {
        try {
            Cipher cipher = Cipher.getInstance(Config.AES_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] encryptedBytes = cipher.doFinal(data.getBytes());
            
            // Combine IV and encrypted data
            byte[] combined = new byte[iv.getIV().length + encryptedBytes.length];
            System.arraycopy(iv.getIV(), 0, combined, 0, iv.getIV().length);
            System.arraycopy(encryptedBytes, 0, combined, iv.getIV().length, encryptedBytes.length);
            
            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new CryptoException("Failed to encrypt data with AES", e);
        }
    }
    
    /**
     * Decrypt data using AES secret key
     * @param encryptedData Base64 encoded encrypted data (includes IV)
     * @param key The AES secret key
     * @return Decrypted data
     * @throws CryptoException if decryption fails
     */
    public static String decryptAES(String encryptedData, SecretKey key) throws CryptoException {
        try {
            byte[] combined = Base64.getDecoder().decode(encryptedData);
            
            // Extract IV
            byte[] iv = new byte[Config.IV_SIZE];
            System.arraycopy(combined, 0, iv, 0, iv.length);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            
            // Extract encrypted data
            byte[] encryptedBytes = new byte[combined.length - iv.length];
            System.arraycopy(combined, iv.length, encryptedBytes, 0, encryptedBytes.length);
            
            Cipher cipher = Cipher.getInstance(Config.AES_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            
            return new String(decryptedBytes);
        } catch (Exception e) {
            throw new CryptoException("Failed to decrypt data with AES", e);
        }
    }
    
    /**
     * Sign data using RSA private key
     * @param data The data to sign
     * @param privateKey The RSA private key
     * @return Base64 encoded signature
     * @throws CryptoException if signing fails
     */
    public static String sign(String data, PrivateKey privateKey) throws CryptoException {
        try {
            Signature signature = Signature.getInstance(Config.SIGNATURE_ALGORITHM);
            signature.initSign(privateKey);
            signature.update(data.getBytes());
            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (Exception e) {
            throw new CryptoException("Failed to sign data", e);
        }
    }
    
    /**
     * Verify signature using RSA public key
     * @param data The data that was signed
     * @param signature Base64 encoded signature
     * @param publicKey The RSA public key
     * @return true if signature is valid, false otherwise
     * @throws CryptoException if verification fails
     */
    public static boolean verify(String data, String signature, PublicKey publicKey) throws CryptoException {
        try {
            Signature sig = Signature.getInstance(Config.SIGNATURE_ALGORITHM);
            sig.initVerify(publicKey);
            sig.update(data.getBytes());
            return sig.verify(Base64.getDecoder().decode(signature));
        } catch (Exception e) {
            throw new CryptoException("Failed to verify signature", e);
        }
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
    public static SecretKey stringToSecretKey(String keyStr) throws CryptoException {
        try {
            byte[] decodedKey = Base64.getDecoder().decode(keyStr);
            return new SecretKeySpec(decodedKey, 0, decodedKey.length, Config.AES_ALGORITHM);
        } catch (Exception e) {
            throw new CryptoException("Failed to convert string to secret key", e);
        }
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
    public static PublicKey stringToPublicKey(String keyStr) throws CryptoException {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(keyStr);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance(Config.RSA_ALGORITHM);
            return kf.generatePublic(spec);
        } catch (Exception e) {
            throw new CryptoException("Failed to convert string to public key", e);
        }
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
    public static PrivateKey stringToPrivateKey(String keyStr) throws CryptoException {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(keyStr);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance(Config.RSA_ALGORITHM);
            return kf.generatePrivate(spec);
        } catch (Exception e) {
            throw new CryptoException("Failed to convert string to private key", e);
        }
    }
    
    /**
     * Create an initialization vector from bytes
     */
    public static IvParameterSpec createIvFromBytes(byte[] iv) {
        return new IvParameterSpec(iv);
    }
}
