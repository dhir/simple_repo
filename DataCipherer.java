import java.nio.charset.Charset;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import com.ericsson.acs.utils.Base64Formater;

/**
 * Utility class for encoding/decoding small amounts of data using ciphers. 
 * <br>The class is designed to encode/decode smaller amounts of data, e.g. strings
 * that are to be stored on file or in a database.
 * <br>All the methods in the class are thread safe as the underlying cipher objects are stored in ThreadLocal variables.
 * @author Peter Nerg (epknerg)
 */
public abstract class DataCipherer
{
	/** The default cipher algorithm.*/
	private transient static final String CIPHER_ALGORITHM = "PBEWithMD5AndDES";
	
    /** The default iteration salt. */
    private transient static final byte[] SALT = { (byte) 0xc7, (byte) 0x73, (byte) 0x21, (byte) 0x8c, (byte) 0x7e, (byte) 0xc8, (byte) 0xee, (byte) 0x99 };

    /** The default iteration count. */
    private transient static final int ITERATION_COUNT = 20;
	
	/** This must never be changed since then the produced encypted/decypted data would not match 
	 * previously created digests. This becomes a problem if there are old digests stored in e.g a database. */
    private transient static final char[] KEY = "asd3s#ASePeteR-RuleZv#eaqwd_asde213d$?cw666c&_aw2c".toCharArray();
    
    /** ThreadLocal storage of encryption enabled cipher objects. */
    private transient static ThreadLocal<Cipher> encryptCipher = new ThreadLocal<Cipher>();    

    /** ThreadLocal storage of decryption enabled cipher objects. */
    private transient static ThreadLocal<Cipher> decryptCipher = new ThreadLocal<Cipher>();

    /**
     * Get the ThreadLocal instance of the encryption enabled Cipher object.
     * @return
     * @throws Exception
     */
	private static Cipher getEncryptCipher() throws Exception
    {
    	Cipher cipher = encryptCipher.get();
    	if(cipher == null)
    	{
    		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(CIPHER_ALGORITHM);    		
    		cipher = Cipher.getInstance(CIPHER_ALGORITHM);
    		cipher.init(Cipher.ENCRYPT_MODE, keyFactory.generateSecret(new PBEKeySpec(KEY)), new PBEParameterSpec(SALT, ITERATION_COUNT));
    		encryptCipher.set(cipher);
    	}
    	
    	return cipher;
    }
    
    /**
     * Get the ThreadLocal instance of the decryption enabled Cipher object.
     * @return
     * @throws Exception
     */
	private static Cipher getDecryptCipher() throws Exception
    {
    	Cipher cipher = decryptCipher.get();
    	if(cipher == null)
    	{
    		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(CIPHER_ALGORITHM);    		
    		cipher = Cipher.getInstance(CIPHER_ALGORITHM);
    		cipher.init(Cipher.DECRYPT_MODE, keyFactory.generateSecret(new PBEKeySpec(KEY)), new PBEParameterSpec(SALT, ITERATION_COUNT));
    		decryptCipher.set(cipher);
    	}
    	
    	return cipher;
    }
	
	/**
	 * Encrypts the provided byte data.
	 * @param b The data to encrypt
	 * @return The encypted data
	 * @throws DVEException
	 */
	public static byte[] encrypt(byte[] b) throws Exception
	{		
		try
		{
			return getEncryptCipher().doFinal(b);
		}
		catch(Exception e)
		{
			throw e;
		}
	}

	/**
	 * Encrypts the provided string data.
	 * <br>The encrypted byte data will be converted to a Base64 formatted string.
	 * @param s The data to encrypt
	 * @return The encypted data
	 * @throws DVEException
	 */
	public static String encrypt(String s) throws Exception
	{
		byte[] encypted = encrypt(s.getBytes(Charset.defaultCharset()));
		String encoded = Base64Formater.encodeBytes(encypted);
		return encoded;
	}

	/**
	 * Decrypts the provided byte data.
	 * @param b The data to decrypt
	 * @return The decrypted data
	 * @throws Exception
	 */
	public static byte[] decrypt(byte[] b) throws Exception
	{
		try
		{
			return getDecryptCipher().doFinal(b);
		}
		catch(Exception e)
		{
			throw e;						
		}
	}

	/**
	 * Decrypts the provided string data.
	 * <br>The string data is expected to be a Base64 formatted string
	 * @param s The data to decrypt
	 * @return The decrypted data
	 * @throws Exception
	 */
	public static String decrypt(String s) throws Exception
	{
		return new String(decrypt(Base64Formater.decode(s)), Charset.defaultCharset());
	}	
	
	/**
	 * This method is invoked by the installation script in order to encrypt data before storing it to file.
	 * <br>The method expects exactly one argument, the data to encrypt.
	 * <br>The encrypted data will be written to <code>System.out.println</code>
	 * @param args
	 * @throws IllegalArgumentException If the argument array size is not one (1)
	 * @throws DVEException In case an errors occurs in the encryption
	 */
	public static void main(String[] args) throws Exception
	{
		if(args.length != 1)
			throw new IllegalArgumentException("Expected exactly one argument");
				
		String encrypted = encrypt(args[0]);
		System.out.println(encrypted);
	}
}
