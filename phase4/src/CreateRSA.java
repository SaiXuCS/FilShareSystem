import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

public class CreateRSA { 
    private static String[] RSA(byte[] data)throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException{
        String[] response= new String[2];
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA");
        keyPair.initialize(2048);
        KeyPair kp = keyPair.genKeyPair();
        Key pubKey = kp.getPublic();
        Key priKey = kp.getPrivate();
        Cipher cipher= Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] encrypted = cipher.doFinal(data);
        String str = new String(encrypted, StandardCharsets.UTF_8);
        response[0]= "\n\nRSA encrypted message is: \n"+str;
        cipher.init(Cipher.DECRYPT_MODE,priKey);
        byte[] plain = cipher.doFinal(encrypted);
        str = new String(plain, StandardCharsets.UTF_8);
        response[1]= "RSA Decrypted message is: \n"+str;
        return response;
    }
    public static String signature(byte[] data, String plainText)throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException{
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA");
        keyPair.initialize(2048);
        KeyPair kp = keyPair.genKeyPair();
        Key pubKey = kp.getPublic();
        Key priKey = kp.getPrivate();
        Cipher cipher= Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, priKey);
        byte[] signature = cipher.doFinal(data);
        cipher.init(Cipher.DECRYPT_MODE,pubKey);
        byte[] getMessageFromSignature = cipher.doFinal(signature);
        String str = new String(getMessageFromSignature, StandardCharsets.UTF_8);
        if(str.equals(plainText)){
            return "correct";
        }else{
            return "wrong";
        }
    }
    public static void main(String[] args) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, FileNotFoundException, IOException, ClassNotFoundException {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA");
        keyPair.initialize(2048);
        KeyPair kp = keyPair.genKeyPair();
        Key pubKey = kp.getPublic();
        Key priKey = kp.getPrivate();
        RSAObject outR= new RSAObject(pubKey, priKey);
        ObjectOutputStream outRSA= new ObjectOutputStream(new FileOutputStream("RSAKeys.bin"));
        outRSA.writeObject(outR);
        outRSA.close();
    }
}










