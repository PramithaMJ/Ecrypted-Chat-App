package Chat.crypto;

import Chat.common.exceptions.CryptoException;
import Chat.network.message.SecureMessage;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.PublicKey;

/**
 * Processes secure messages - handling encryption, decryption, signing and verification
 */
public class SecureMessageProcessor {
    private final KeyManager keyManager;
    
    public SecureMessageProcessor(KeyManager keyManager) {
        this.keyManager = keyManager;
    }
    
    /**
     * Encrypt a message for a specific peer
     * @param message the message content
     * @param peerId the peer identifier
     * @param sender the sender identifier
     * @return the encrypted message object
     * @throws CryptoException if encryption fails
     */
    public SecureMessage encryptMessage(String message, String peerId, String sender) throws CryptoException {
        if (!keyManager.hasSessionWith(peerId)) {
            throw new CryptoException("No secure session established with " + peerId);
        }
        
        SecretKey sessionKey = keyManager.getSessionKey(peerId);
        IvParameterSpec iv = CryptoUtil.generateIV();
        
        // Encrypt the message with AES
        String encryptedContent = CryptoUtil.encryptAES(message, sessionKey, iv);
        
        // Create a secure message
        SecureMessage secureMsg = new SecureMessage(
            SecureMessage.MessageType.ENCRYPTED_MESSAGE,
            sender,
            encryptedContent
        );
        
        // Sign the message with our private key for authentication
        String signature = CryptoUtil.sign(message, keyManager.getLocalPrivateKey());
        secureMsg.setSignature(signature);
        
        return secureMsg;
    }
    
    /**
     * Decrypt a secure message
     * @param message the secure message
     * @return the decrypted content
     * @throws CryptoException if decryption fails
     */
    public String decryptMessage(SecureMessage message) throws CryptoException {
        String sender = message.getSender();
        
        if (!keyManager.hasSessionWith(sender)) {
            throw new CryptoException("No secure session established with " + sender);
        }
        
        SecretKey sessionKey = keyManager.getSessionKey(sender);
        
        // Decrypt the message content
        return CryptoUtil.decryptAES(message.getContent(), sessionKey);
    }
    
    /**
     * Verify the signature of a message
     * @param message the secure message
     * @param decryptedContent the decrypted content
     * @return true if signature is valid
     * @throws CryptoException if verification fails
     */
    public boolean verifyMessageSignature(SecureMessage message, String decryptedContent) throws CryptoException {
        String sender = message.getSender();
        String signature = message.getSignature();
        
        if (signature == null) {
            return false;
        }
        
        PublicKey senderPublicKey = keyManager.getPeerPublicKey(sender);
        if (senderPublicKey == null) {
            throw new CryptoException("No public key available for " + sender);
        }
        
        return CryptoUtil.verify(decryptedContent, signature, senderPublicKey);
    }
    
    /**
     * Create a secure challenge message for authentication
     * @param sender the sender identifier 
     * @return the challenge message
     */
    public SecureMessage createAuthChallenge(String sender) {
        byte[] challengeBytes = new byte[32];
        new java.security.SecureRandom().nextBytes(challengeBytes);
        String challenge = java.util.Base64.getEncoder().encodeToString(challengeBytes);
        
        return new SecureMessage(
            SecureMessage.MessageType.AUTH_CHALLENGE,
            sender,
            challenge
        );
    }
    
    /**
     * Create a response to an authentication challenge
     * @param challenge the challenge message
     * @param sender the sender identifier
     * @return the response message
     * @throws CryptoException if signing fails
     */
    public SecureMessage createAuthResponse(String challenge, String sender) throws CryptoException {
        String signedResponse = CryptoUtil.sign(challenge, keyManager.getLocalPrivateKey());
        
        return new SecureMessage(
            SecureMessage.MessageType.AUTH_RESPONSE,
            sender,
            signedResponse
        );
    }
    
    /**
     * Verify an authentication response
     * @param challenge the original challenge
     * @param response the response message
     * @return true if authentication is successful
     * @throws CryptoException if verification fails
     */
    public boolean verifyAuthResponse(String challenge, SecureMessage response) throws CryptoException {
        String sender = response.getSender();
        PublicKey senderPublicKey = keyManager.getPeerPublicKey(sender);
        
        if (senderPublicKey == null) {
            throw new CryptoException("No public key available for " + sender);
        }
        
        return CryptoUtil.verify(challenge, response.getContent(), senderPublicKey);
    }
}
