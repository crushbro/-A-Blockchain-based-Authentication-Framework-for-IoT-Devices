package blockchainProject;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Device {
	
	private BigInteger nonce;
	private Random rand;
	private MessageDigest hash;
	private int TID;
	private int address; // encrypt with publickey
	private PublicKey pubkey;
	private PrivateKey privkey;
	private KeyFactory kf;
	private Signature signature;
	private PublicKey otherPublicKey;

	public Device() throws NoSuchAlgorithmException {
		rand = new Random();
		hash = MessageDigest.getInstance("SHA-256");
		kf = KeyFactory.getInstance("RSA");
		signature = Signature.getInstance("SHA256withRSA");
	}
	
	public byte[] Hash(String input) {
		return hash.digest(input.getBytes());
	}
	
	// setp 4, 8, and 12 need clarification
	
	// steps 1, 2, 3
	public byte[] getEncryptedAddress(int TID) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		PublicKey pubkey = Blockchain.getPublicKey(TID); // step 1
		byte[] enc_address = encrypt(pubkey, intToBytes(address)); // step 2
		return enc_address; // step 3
	}
	
	// steps 4, 5, 6, 7
	public byte[] getEncryptedHash(int enc_address) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
		int TID_address = enc_address;
		otherPublicKey = Blockchain.getPublicKey(TID_address); // step 5
		int new_nonce = rand.nextInt(); // step 6
		long new_timestamp = System.currentTimeMillis(); // step 6
		
		return encrypt(otherPublicKey, Hash(""+new_nonce+new_timestamp)); // step 7
	}
	
	// steps 9, 10, 11
	public Message digitalSignature(byte[] hash) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException {
		byte[] hash_value = decrypt(hash);
		signature.update(hash_value);
		byte[] signedHash = signature.sign();
		Message authMessage = new Message(signedHash, TID, hash_value);
		return authMessage;
	}
	
	// step 12
	public boolean authFinal(Message m) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, SignatureException {
		signature.initVerify(otherPublicKey);
		signature.update(m.getHash());
		boolean verify = signature.verify(m.getSignature());
		return verify;
	}
	
	public byte[] encrypt(PublicKey pubkey, byte[] inputdata) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, pubkey);
		
		byte[] encrypted_data = cipher.doFinal(inputdata);
		
		return encrypted_data;
	}
	
	// this is for step 4
	public byte[] decrypt(byte[] inputdata) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
		
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privkey);
		
		byte[] decrypted_data = cipher.doFinal(inputdata);
		return decrypted_data;
	}
	
	private byte[] intToBytes(int i) {
	    ByteBuffer bb = ByteBuffer.allocate(4); 
	    bb.putInt(i); 
	    return bb.array();
	}
	
	private int bytesToInt(byte[] value) {
		ByteBuffer bb = ByteBuffer.wrap(value);
		return bb.getInt();
	}
	
	// send own encrypted address
	
	public Message Initialization1() {
		nonce = new BigInteger(512, rand);
		long timestamp = System.currentTimeMillis();
		return new Message(nonce, timestamp, Hash(""+nonce+timestamp));
	}
	
	public void Initialization3(Message m2) throws InvalidKeySpecException, InvalidKeyException {
		// Verify signature
		// Verify timestamp
		// Verify hash
		/*
		byte[] TID_x = m2.getTID_x();
		byte[] TID_bytes = new byte[TID_x.length];
		byte[] nonce_bytes = (""+nonce).getBytes();
		for (int i = 0; i < TID_x.length; i++) {
			TID_bytes[i] = (byte) (TID_x[i] ^ nonce_bytes[i]);
		}
		ByteBuffer bb = ByteBuffer.wrap(TID_bytes);
		TID = bb.getInt();
		address = TID;
		byte[] priv_x = m2.getPriv_x();
		byte[] privKey_encoded = new byte[priv_x.length];
		for (int i = 0; i < nonce_bytes.length; i++) {
			privKey_encoded[i] = (byte) (priv_x[i] ^ nonce_bytes[i]);
		}*/
		ByteBuffer bb = ByteBuffer.wrap(nonce.xor(m2.getTID_x()).toByteArray());
		TID = bb.getInt();
		byte[] privKey_encoded = nonce.xor(m2.getPriv_x()).toByteArray();
		privkey = kf.generatePrivate(new PKCS8EncodedKeySpec(privKey_encoded));
		signature.initSign(privkey);
		pubkey = Blockchain.getPublicKey(TID);
	}
	
	public int getTID() {
		return TID;
	}
}
