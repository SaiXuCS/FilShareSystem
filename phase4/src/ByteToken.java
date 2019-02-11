import java.io.Serializable;

public class ByteToken implements Serializable{
    public byte[] token;

    public byte[] getToken() {
        return token;
    }

    public ByteToken(byte[] token){
        this.token= token;
    }

}