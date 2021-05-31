package etf.openpgp.mn170085d_dm170084d.keys;

import etf.openpgp.mn170085d_dm170084d.Globals;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.io.*;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;

public class KeyReaderWriter {
    private PGPSecretKeyRingCollection privateKeys;
    private PGPPublicKeyRingCollection publicKeys;

    public void readKeys() {
        try {
            File publicKeysFile = new File(Globals.publicKeysPath);
            if (publicKeysFile.exists()) {
                InputStream inputStream = new ArmoredInputStream(new FileInputStream(publicKeysFile));
                publicKeys = new PGPPublicKeyRingCollection(inputStream, new JcaKeyFingerprintCalculator());
            } else {
                publicKeys = new PGPPublicKeyRingCollection(new LinkedList<>());
            }

            File privateKeysFile = new File(Globals.privateKeysPath);
            if (privateKeysFile.exists()) {
                InputStream inputStream = new ArmoredInputStream(new FileInputStream(privateKeysFile));
                privateKeys = new PGPSecretKeyRingCollection(inputStream, new JcaKeyFingerprintCalculator());
            } else {
                privateKeys = new PGPSecretKeyRingCollection(new LinkedList());
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        }
    }

    public boolean savePGPSecretKeyRing(PGPSecretKeyRing secretKeyRing) {
        try (OutputStream secretOut = new ArmoredOutputStream(new FileOutputStream(Globals.privateKeysPath))){
            if (secretKeyRing != null) {
                this.privateKeys = PGPSecretKeyRingCollection.addSecretKeyRing(this.privateKeys, secretKeyRing);
            }
            this.privateKeys.encode(secretOut);
            return true;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return false;
    }

    public boolean savePGPPublicKeyRing(PGPPublicKeyRing publicKeyRing) {
        try (OutputStream secretOut = new ArmoredOutputStream(new FileOutputStream(Globals.publicKeysPath))) {
            if (publicKeyRing != null) {
                this.publicKeys = PGPPublicKeyRingCollection.addPublicKeyRing(this.publicKeys, publicKeyRing);
            }
            this.publicKeys.encode(secretOut);
            return true;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return false;
    }

    public ObservableList<KeyGuiVisualisation> getPrivateKeys() {
        ObservableList<KeyGuiVisualisation> privateKeysList = FXCollections.observableArrayList();

        Iterator<PGPSecretKeyRing> iterator = this.privateKeys.getKeyRings();
        PGPSecretKeyRing secretKeyRing;

        while (iterator.hasNext()) {
            secretKeyRing = iterator.next();
            Iterator<PGPSecretKey> keyIterator = secretKeyRing.getSecretKeys();
            PGPSecretKey masterKey = keyIterator.next();

            // One master key can have multiple sub keys.
            while (keyIterator.hasNext()) {
                PGPSecretKey subKey = keyIterator.next();   // returns the key id of the public key (this we need)

                long id = subKey.getKeyID();
                String owner = masterKey.getUserIDs().next();
                Date date = subKey.getPublicKey().getCreationTime();

                privateKeysList.add(new KeyGuiVisualisation(id, owner, date));
            }
        }

        return privateKeysList;
    }

    public boolean deleteKey(long idToDelete, String passphrase) {
        try {
            Iterator<PGPSecretKeyRing> iterator = this.privateKeys.getKeyRings();
            PGPSecretKeyRing secretKeyRing;

            while (iterator.hasNext()) {
                secretKeyRing = iterator.next();
                Iterator<PGPSecretKey> keyIterator = secretKeyRing.getSecretKeys();
                PGPSecretKey masterKey = keyIterator.next();

                // One master key can have multiple sub keys.
                while (keyIterator.hasNext()) {
                    PGPSecretKey subKey = keyIterator.next();   // returns the key id of the public key (this we need)

                    long id = subKey.getKeyID();

                    if (id == idToDelete) {
                        subKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase.toCharArray()));

                        this.privateKeys = this.privateKeys.removeSecretKeyRing(this.privateKeys, this.privateKeys.getSecretKeyRing(id));
                        this.savePGPSecretKeyRing(null);

                        return true;
                    }
                }
            }
        } catch (PGPException e) {
            System.out.println("Lozinka pogresna.");
            // e.printStackTrace();
        }

        return false;
    }
}
