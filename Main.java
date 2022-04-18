package blockchainProject;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Main {
	
	public static final int serverID = 1;

	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		// TODO Auto-generated method stub
		// Create the objects for the server and devices
		Server server = new Server(serverID);
		Device device1 = new Device();
		Device device2 = new Device();
		
		// Initialize both devices
		Message im1 = device1.Initialization1();
		Message im2 = server.Initialization2(im1);
		device1.Initialization3(im2);
		
		Message im3 = device2.Initialization1();
		Message im4 = server.Initialization2(im3);
		device2.Initialization3(im4);
		
		// Authentication Phase
		byte[] enc_address = device1.getEncryptedAddress(device2.getTID());
		byte[] enc_message = device2.getEncryptedHash(device1.getTID());
		Message authMessage = device1.digitalSignature(enc_message);
		boolean verify = device2.authFinal(authMessage);
		System.out.println();
		System.out.println("Authentication verification: " + verify);
	}
}
