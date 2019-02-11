import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import org.bouncycastle.crypto.agreement.srp.SRP6Server;
import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;

import java.math.BigInteger;
import java.security.SecureRandom;

public class SRPtest {
    public static void main(String[] args) throws CryptoException {
        byte[] I = "username".getBytes();
        byte[] P = "password".getBytes();
        byte[] s = new byte[16];
        BigInteger g = new BigInteger("92356305589111923938577510282610817331995024932934095090679051297951462382210");	//g and p used to apply diffie hellman
        BigInteger p = new BigInteger("88397245229545427575603639876844588157137584548492958882453140645069084311605");
        new SecureRandom().nextBytes(s);
        System.out.println(s.toString());
        SRP6VerifierGenerator gen = new SRP6VerifierGenerator();
        gen.init(p, g, new SHA256Digest());
        BigInteger v = gen.generateVerifier(s, I, P);
        System.out.println(v.toString(10));
        SRP6Client client = new SRP6Client();
        client.init(p, g, new SHA256Digest(), new SecureRandom());

        SRP6Server server = new SRP6Server();
        server.init(p, g, v, new SHA256Digest(), new SecureRandom());

        BigInteger A = client.generateClientCredentials(s, I, P);
        BigInteger B = server.generateServerCredentials();
        BigInteger clientS = client.calculateSecret(B);
        client.verifyServerEvidenceMessage(B);
        BigInteger serverS = server.calculateSecret(A);
        server.verifyClientEvidenceMessage(A);
        System.out.println(client.calculateSessionKey().toString(16));
        System.out.println(client.calculateSessionKey().toString(16));
        if (!clientS.equals(serverS))
        {
            System.out.println("SRP agreement failed - client/server calculated different secrets");
        }
    }
    }
