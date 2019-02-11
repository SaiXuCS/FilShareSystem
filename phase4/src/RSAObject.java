import java.security.*;
import java.util.*;
public class RSAObject implements java.io.Serializable{
	Key pub, pri;
	public RSAObject(Key publicKey, Key privateKey){
		pub= publicKey;
		pri= privateKey;
	}
	public Key returnPublic(){
		return pub;
	}
	public Key returnPrivate(){
		return pri;
	}
}
