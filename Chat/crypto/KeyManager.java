package Chat.crypto;

import Chat.common.exceptions.CryptoException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;

/**
 * Manages cryptographic keys for the application
 */
public class KeyManager {
    // Store keys
    private KeyPair localKeyPair;
    private Map<String, PublicKey> peerPublicKeys;
    private Map<String, SecretKey> sessionKeys;
    
    public KeyManager() {
        peerPublicKeys = new HashMap<>();
        sessionKeys = new HashMap<>();
    }
    
    /**
     * Initialize local key pair
     * @throws CryptoException if generation fails
     */
    public void initializeKeyPair() throws CryptoException {
        localKeyPair = CryptoUtil.generateRSAKeyPair();
    }
    
    /**
     * Get local public key
     * @return the public key, or null if not initialized
     */
    public PublicKey getLocalPublicKey() {
        return localKeyPair != null ? localKeyPair.getPublic() : null;
    }
    
    /**
     * Get local private key
     * @return the private key, or null if not initialized
     */
    public PrivateKey getLocalPrivateKey() {
        return localKeyPair != null ? localKeyPair.getPrivate() : null;
    }
    
    /**
     * Store a peer's public key
     * @param peerId the peer identifier
     * @param publicKey the public key
     */
    public void storePeerPublicKey(String peerId, PublicKey publicKey) {
        peerPublicKeys.put(peerId, publicKey);
    }
    
    /**
     * Get a peer's public key
     * @param peerId the peer identifier
     * @return the public key, or null if not found
     */
    public PublicKey getPeerPublicKey(String peerId) {
        return peerPublicKeys.get(peerId);
    }
    
    /**
     * Generate and store a session key for a peer
     * @param peerId the peer identifier
     * @return the generated session key
     * @throws CryptoException if key generation fails
     */
    public SecretKey generateSessionKey(String peerId) throws CryptoException {
        SecretKey key = CryptoUtil.generateAESKey();
        sessionKeys.put(peerId, key);
        return key;
    }
    
    /**
     * Store a session key for a peer
     * @param peerId the peer identifier
     * @param key the session key
     */
    public void storeSessionKey(String peerId, SecretKey key) {
        sessionKeys.put(peerId, key);
    }
    
    /**
     * Get a session key for a peer
     * @param peerId the peer identifier
     * @return the session key, or null if not found
     */
    public SecretKey getSessionKey(String peerId) {
        return sessionKeys.get(peerId);
    }
    
    /**
     * Check if a session exists with a peer
     * @param peerId the peer identifier
     * @return true if a session exists
     */
    public boolean hasSessionWith(String peerId) {
        return sessionKeys.containsKey(peerId) && peerPublicKeys.containsKey(peerId);
    }
    
    /**
     * Remove all keys associated with a peer
     * @param peerId the peer identifier
     */
    public void removePeer(String peerId) {
        peerPublicKeys.remove(peerId);
        sessionKeys.remove(peerId);
    }
}
