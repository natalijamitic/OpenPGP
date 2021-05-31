package etf.openpgp.mn170085d_dm170084d.keys;

import javafx.collections.ObservableList;
import org.bouncycastle.openpgp.*;

public class KeyHelper {
    private KeyReaderWriter keyReaderWriter;
    private KeyGenerator keyGenerator;

    public KeyHelper() {
        this.keyGenerator = new KeyGenerator();
        this.keyReaderWriter = new KeyReaderWriter();
        this.keyReaderWriter.readKeys();
    }

    public boolean generateRSAKey(String name, String mail, String passphrase, String algorithm) {
        String identity = name + "~" + mail;
        int keySize = Integer.parseInt(algorithm.substring(4));

        PGPSecretKeyRing secretKeyRing = this.keyGenerator.generateRSAPGPSecretKeyRing(identity, passphrase, keySize);

        return this.keyReaderWriter.savePGPSecretKeyRing(secretKeyRing);
    }

    public ObservableList<KeyGuiVisualisation> getPrivateKeys() {
        return this.keyReaderWriter.getPrivateKeysVisaulised();
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
