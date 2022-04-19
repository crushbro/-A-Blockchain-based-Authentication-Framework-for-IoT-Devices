package blockchainProject;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Random;

public class Server {

	KeyPairGenerator kpg;
	KeyPair keypair;
	Blockchain chain;
	Random rand;
	MessageDigest hash;
	Signature signature;
	int serverID;
	
	public Server(int serverID) throws NoSuchAlgorithmException, InvalidKeyException {
		this.serverID = serverID;
		kpg = KeyPairGenerator.getInstance("RSA");
		keypair = kpg.generateKeyPair();
		chain = new Blockchain();
		chain.generateGenesis();
		chain.addKey(keypair.getPublic(), serverID);
		rand = new Random();
		hash = MessageDigest.getInstance("SHA-256");
		signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(keypair.getPrivate());
	}
	
	public byte[] Hash(String input) {
		return hash.digest(input.getBytes());
	}
	
	public Message Initialization2(Message m1) throws SignatureException, NoSuchAlgorithmException {
		// Decrypt with private key
		// verify timestamp
		// verify hash
		KeyPair deviceKeys = kpg.generateKeyPair();
		int TID = rand.nextInt();	// Device's true id
		chain.addKey(deviceKeys.getPublic(), TID);

		// Print statements for demonstration purposes
		System.out.println("Device ID: " + TID);
		System.out.println(deviceKeys.getPublic());
		System.out.println();
		
		ByteBuffer bb = ByteBuffer.allocate(4);
		bb.putInt(TID);
		byte[] id_bytes = bb.array();
		BigInteger TID_x = m1.getNonce().xor(new BigInteger(id_bytes));
		BigInteger priv_x = m1.getNonce().xor(new BigInteger(deviceKeys.getPrivate().getEncoded()));
		/*
		byte[] nonce_bytes = (""+m1.getNonce()).getBytes();
		byte[] TID_x = new byte[id_bytes.length];
		for (int i = 0; i < id_bytes.length; i++) {
			TID_x[i] = (byte) (id_bytes[i] ^ nonce_bytes[i]);
		}
		byte[] privateKey_bytes = deviceKeys.getPrivate().getEncoded();
		byte[] priv_x = new byte[privateKey_bytes.length];
		for (int i = 0; i < privateKey_bytes.length; i++) {
			for (int j = 0; j < nonce_bytes.length; j++) {
				if (i < privateKey_bytes.length-1) {
					i++;
					priv_x[i] = (byte) (privateKey_bytes[i] ^ nonce_bytes[j]);
				}	
			}
		}*/
		long timestamp = System.currentTimeMillis();
		byte[] temp = Hash(""+TID_x+priv_x+timestamp);
		signature.update(temp);
		return new Message(TID_x, priv_x, timestamp, temp, signature.sign());
	}
}
