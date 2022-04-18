package blockchainProject;

import java.math.BigInteger;

public class Message {

	private BigInteger nonce;
	private int TID;
	private long timestamp;
	private byte[] hash;
	private BigInteger TID_x; // devices true ID
	private BigInteger priv_x;
	private byte[] signature;
	
	public Message(BigInteger nonce, long timestamp, byte[] hash) { // initialization message to the server
		this.nonce = nonce;
		this.timestamp = timestamp;
		this.hash = hash;
	}
	
	public Message(BigInteger TID_x, BigInteger priv_x, long timestamp, byte[] hash, byte[] signature) {
		this.TID_x = TID_x;
		this.priv_x = priv_x;
		this.timestamp = timestamp;
		this.hash = hash;
		this.signature = signature;
	}
	
	public Message(byte[] signedHash, int TID, byte[] hash) {
		this.signature = signedHash;
		this.TID = TID;
		this.hash = hash;
	}

	public BigInteger getNonce() {
		return nonce;
	}

	public long getTimestamp() {
		return timestamp;
	}

	public byte[] getHash() {
		return hash;
	}

	public BigInteger getTID_x() {
		return TID_x;
	}

	public BigInteger getPriv_x() {
		return priv_x;
	}

	public byte[] getSignature() {
		return signature;
	}
	
	public int getTID() {
		return TID;
	}
}
