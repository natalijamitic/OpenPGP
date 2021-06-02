package etf.openpgp.mn170085d_dm170084d.keys;

import javafx.collections.ObservableList;
import org.bouncycastle.openpgp.*;

import java.util.Iterator;

public class KeyHelper {
    private KeyReaderWriter keyReaderWriter;
    private KeyGenerator keyGenerator;

    public KeyHelper() {
        this.keyGenerator = new KeyGenerator();
        this.keyReaderWriter = new KeyReaderWriter();
        this.keyReaderWriter.readKeys();
    }

    public boolean generateRSAKey(String name, String mail, String passphrase, String algorithm) {
        String identity = name + " <" + mail + ">";
        int keySize = Integer.parseInt(algorithm.substring(4));

        PGPSecretKeyRing secretKeyRing = this.keyGenerator.generateRSAPGPSecretKeyRing(identity, passphrase, keySize);

        return this.keyReaderWriter.savePGPSecretKeyRing(secretKeyRing);
    }

    public ObservableList<KeyGuiVisualisation> getPrivateKeys() {
        return this.keyReaderWriter.getPrivateKeys();
    }

    public ObservableList<KeyGuiVisualisation> getPublicKeys() {
        return this.keyReaderWriter.getPublicKeys();
    }

    public boolean deleteKey(long id, String password) {
        return this.keyReaderWriter.deleteKey(id, password);
    }

    public boolean exportPrivateKey(String filePath, long id) {
        return this.keyReaderWriter.exportPrivateKey(filePath, id, null);
    }

    public boolean exportPublicKey(String filePath, long id) {
        return this.keyReaderWriter.exportPublicKey(filePath, id);
    }

    public boolean importPrivateKey(String filePath) {
        return this.keyReaderWriter.importPrivateKey(filePath);
    }

    public boolean importPublicKey(String filePath) {
        return this.keyReaderWriter.importPublicKey(filePath);
    }

    public PGPPublicKeyRing getPublicKeyRingById(long Id)
    {
        return this.keyReaderWriter.getPublicKeyRingForID(Id);
    }

    public PGPSecretKey getSecretKeyById(long Id)
    {
        PGPSecretKey secretKey = this.keyReaderWriter.getSecretSubKeyByID(Id);
        return secretKey;
    }

    public PGPPublicKey extractPublicKey(PGPPublicKeyRing publicKeyRing)
    {
        Iterator<PGPPublicKey> publicKeys = publicKeyRing.getPublicKeys();
        PGPPublicKey publicKey = publicKeys.next();
        publicKey = publicKeys.next();
        return publicKey;
    }


//    public ObservableList<KeyGuiVisualisation> getPublicKeys() {
//        return this.keyReaderWriter.getPublicKeysVisaulised();
//    }

    public static void main(String[] args) {
        KeyHelper keyGen = new KeyHelper();

        keyGen.generateRSAKey("naca", "naca@ntec.ch", "naca123", "RSA 1024");
        keyGen.generateRSAKey("naca", "naca@ntec.ch", "naca123", "RSA 2048");
        keyGen.generateRSAKey("naca", "naca@ntec.ch", "naca123", "RSA 4096");
    }
}
