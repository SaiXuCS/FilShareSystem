
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.KeyGenerator;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author sai xu
 */
public class GroupN implements java.io.Serializable{
    ArrayList<Entry> groupCipher= new ArrayList<>();
    public void addCipher() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException{
        Entry newEntry= new Entry();
        groupCipher.add(newEntry);
    }
    public ArrayList<Entry> getCipher(){
        return groupCipher;
    }
}
