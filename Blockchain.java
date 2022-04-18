package blockchainProject;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Iterator;
import java.util.LinkedList;

public class Blockchain {

	static LinkedList<Block> main_bc = new LinkedList<>();
	
	
	public Blockchain() {
		
	}
	
	public void generateGenesis() throws NoSuchAlgorithmException {
		main_bc.addFirst(new Block(null, null, -1));
	}
	
	public void addKey(PublicKey pub, int TID) throws NoSuchAlgorithmException { //
		main_bc.add(new Block(main_bc.getLast().getHash(), pub, TID));
	}
	
	public static PublicKey getPublicKey(int TID) {
		
		Iterator<Block> it = main_bc.iterator();
		
		while(it.hasNext()) {
			Block temp = it.next();
			if(temp.getTID() == TID)
				return temp.getPub();
		}
		
		return null;
		
	}
}
