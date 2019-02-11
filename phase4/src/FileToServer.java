import javax.crypto.SecretKey;
import java.io.Serializable;

public class FileToServer implements Serializable{
	public byte[] iv;
	public byte[] key;
	public byte[] signToken;
	public byte[] encryptedToken;
	public byte[] tokenEncrypted;
	public SecretKey	tokenKey;
	public byte[]	tokenKeySigned;
	public byte[] tokenIV;
	public FileToServer(byte[] a, byte[] b, byte[]c, byte[] d,byte[] e,SecretKey f, byte[] g,byte[] h){
		iv= a;
		key= b;
		signToken= c;
		encryptedToken= d;
		tokenEncrypted = e;
		tokenKey = f;
		tokenKeySigned = g;
		tokenIV = h;
	}
}
