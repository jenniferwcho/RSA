import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

/**
* <h1>RSA: Encrypt and decrypt the message<h1> 
* RSA is one of the first public-key cryptosystems and is widely 
* used for secure data transmission.
*
* @author  Jennifer Cho
* @since   2018-11-14 
*/
public class RSA {
	// random generator
	private final static SecureRandom random = new SecureRandom();
	
	private BigInteger p; // prime number
	private BigInteger q; // prime number
	private BigInteger n; // p*q
	private BigInteger e; // public key where gcd(e,phi)=1
	private BigInteger d; // private key where ed = 1 mod phi

	/**
	 * This is the main method getting encrpyt message and 
	 * decrypted message from the users.
	 * @exception IOException On input error.
	 * @see IOException
	 */
	public static void main(String[] args) throws IOException{
		// Get personal RSA Information(public key and private key)
//		RSA_main myInf = new RSA_main(100);
//		System.out.println(myInf.toString());
		
		Scanner input = new Scanner(System.in);
		
		// Encrypt the message and print out
		System.out.print("Enter a message for the encryption: ");
		String s1 = "";
		s1 = input.nextLine();
		System.out.println(encrypt(s1));
		
		// Get message from user, decrypt the message, and print out
		System.out.print("Enter a message for the decryption: ");
		String s2 = "";
		s2 = input.nextLine();
		System.out.println(decrypt(s2));
		
		input.close();
	}
	
	/**
	* This method is used to setup personal RSA information.
	* Based on bitlength chosen by the user, it initializes
	* public keys(n,e) and private key(d).
	* @param N bit length for how big our p,q,e will be
	*/
	RSA(int N){
		p = BigInteger.probablePrime(N, random);
		q = BigInteger.probablePrime(N, random);
		BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		
		n = p.multiply(q);
		e = BigInteger.probablePrime(N/2, random);
		// while e does not satisfy the condition such that gcd(phi,e)=1,
		// increment 2 by one until e meets the condition.
		// Note: e is always 1 < e < phi
		while(phi.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0) {
			e.add(BigInteger.ONE);
		}
		d = e.modInverse(phi); // ed is equiv to 1 mod phi
	}
	
	/**
	* This method is used to return all generated personal RSA
	* information.
	* @return String This all personal RSA info
	*/
	public String toString() {
		StringBuilder s = new StringBuilder();
		s.append("p= " + p + "\n");
		s.append("q= " + q + "\n");
		s.append("n= " + n + "\n");
		s.append("e= " + e + "\n");
		s.append("d= " + d + "\n");
		return s.toString();
	}
	
	/**
	* This method is used to encrypt the message. The encryption
	* is based on the pre-generated personal RSA public keys(n,e).
	* @param String message to encrypt
	* @return String encrypted message(string of numbers)
	*/
	public static String encrypt(String message) {
		BigInteger n = new BigInteger("769750914680484372200078422578788743792190453917708306205411");
		BigInteger e = new BigInteger("823738732813999");
		BigInteger numL,encL;
		StringBuilder result = new StringBuilder();
		
		for(char letter : message.toCharArray()) {
			numL = BigInteger.valueOf(letter); // each letter in big integer format
			encL = numL.modPow(e,n); // each encoded letter
			result.append(encL + " ");
		}
		return result.toString();
	}
	
	/**
	* This method is used to decrypt the message. The decryption
	* is based on the pre-generated personal RSA private key(n,d).
	* @param String message to decrypt(string of numbers)
	* @return String decrypted message
	*/
	public static String decrypt(String encryptedM) {
		BigInteger numL,decInt;
		String decL;
		BigInteger n = new BigInteger("769750914680484372200078422578788743792190453917708306205411");
		BigInteger d = new BigInteger("353343052159423642183327550893401946314922128579120163105999");
		StringBuilder result = new StringBuilder();
		
		String[] letters = encryptedM.split(" ");
		for(String letter : letters) {
			numL = new BigInteger(letter); // each letter to big integer format
			decInt = numL.modPow(d, n); // decoded letter(BigInteger format)
			decL = new String(decInt.toByteArray()); // decoded letter(string format)
			result.append(decL);
		}
		return result.toString();
	}
}
