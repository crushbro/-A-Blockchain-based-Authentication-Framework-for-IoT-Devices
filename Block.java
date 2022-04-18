package blockchainProject;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class Block {
	
	private MessageDigest md;
	
	private byte[] hash;
	private byte[] prevHash;
	private long timestamp;
	
	private int TID;
	private PublicKey pub;
	
	public Block() {
		
	}
	
	public Block(byte[] prevHash, PublicKey pub, int TID) throws NoSuchAlgorithmException {
		timestamp = System.currentTimeMillis();
		this.prevHash = prevHash;
		this.pub = pub;
		this.TID = TID;
		md = MessageDigest.getInstance("SHA-256");
		hash = md.digest((""+prevHash+timestamp+TID+pub).getBytes());
	}

	public MessageDigest getMd() {
		return md;
	}

	public byte[] getHash() {
		return hash;
	}

	public byte[] getPrevHash() {
		return prevHash;
	}

	public long getTimestamp() {
		return timestamp;
	}

	public int getTID() {
		return TID;
	}

	public PublicKey getPub() {
		return pub;
	}

	
	
	
	
	
	
	
	
	

}
