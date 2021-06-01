package etf.openpgp.mn170085d_dm170084d.keys;

import etf.openpgp.mn170085d_dm170084d.Globals;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.awt.*;
import java.io.*;
import java.util.*;
import java.util.List;

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
        try (OutputStream secretOut = new ArmoredOutputStream(new FileOutputStream(Globals.privateKeysPath))) {
            if (secretKeyRing != null) {
                this.privateKeys = PGPSecretKeyRingCollection.addSecretKeyRing(this.privateKeys, secretKeyRing);
            }
            this.privateKeys.encode(secretOut);
            return true;
        } catch(IllegalArgumentException e) {
            System.out.println("duplo");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        this.savePGPPublicKeyRing(null);
        return false;
    }

    public boolean savePGPPublicKeyRing(PGPPublicKeyRing publicKeyRing) {
        try (OutputStream secretOut = new ArmoredOutputStream(new FileOutputStream(Globals.publicKeysPath))) {
            if (publicKeyRing != null) {
                this.publicKeys = PGPPublicKeyRingCollection.addPublicKeyRing(this.publicKeys, publicKeyRing);
            }
            this.publicKeys.encode(secretOut);
            System.out.println("sacuvano");
            return true;
        } catch(IllegalArgumentException e) {
            System.out.println("duplo");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        this.savePGPPublicKeyRing(null);
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

    public ObservableList<KeyGuiVisualisation> getPublicKeys() {
        ObservableList<KeyGuiVisualisation> publicKeysList = FXCollections.observableArrayList();

        Iterator<PGPPublicKeyRing> iterator = this.publicKeys.getKeyRings();
        PGPPublicKeyRing publicKeyRing;

        while (iterator.hasNext()) {
            publicKeyRing = iterator.next();
            Iterator<PGPPublicKey> keyIterator = publicKeyRing.getPublicKeys();
            PGPPublicKey masterKey = keyIterator.next();

            // One master key can have multiple sub keys.
            while (keyIterator.hasNext()) {
                PGPPublicKey subKey = keyIterator.next();   // returns the key id of the public key (this we need)

                long id = subKey.getKeyID();
                String owner = masterKey.getUserIDs().next();
                Date date = subKey.getCreationTime();

                publicKeysList.add(new KeyGuiVisualisation(id, owner, date));
            }
        }

        return publicKeysList;
    }

    public boolean importPrivateKey(String path) {
        try (InputStream inputStream = new ArmoredInputStream(new FileInputStream(path))) {
            PGPSecretKeyRing secretKeyRing = new PGPSecretKeyRing(inputStream, new JcaKeyFingerprintCalculator());
            return this.savePGPSecretKeyRing(secretKeyRing);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        }

        return false;
    }

    public boolean importPublicKey(String path) {
        try (InputStream inputStream = new ArmoredInputStream(new FileInputStream(path))) {
            PGPPublicKeyRing publicKeyRing = new PGPPublicKeyRing(inputStream, new JcaKeyFingerprintCalculator());
            return this.savePGPPublicKeyRing(publicKeyRing);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return false;
    }

    public boolean exportPrivateKey(String parentPath, long id, String passphrase) {
        PGPSecretKey subKey = this.getSecretSubKeyByID(id);
        if (subKey == null) {
            return false;
        }

        //TODO: Check if needed;
//        boolean result = this.checkSubKeyWithPassphrase(subKey, passphrase);
//        if (!result) {
//            return false;
//        }

        String fileName= "privateKeyExported_" + (new Date()).getTime() + ".asc";
        File exportFile = new File(parentPath, fileName);

        try (OutputStream secretOut = new ArmoredOutputStream(new FileOutputStream(exportFile))) {
            PGPSecretKeyRing secretKeyRing = this.privateKeys.getSecretKeyRing(id);
            secretKeyRing.encode(secretOut);
            this.openFileLocation(parentPath);
            return true;
        } catch (PGPException | IOException e) {
            e.printStackTrace();
        }

        return false;
    }

    public boolean exportPublicKey(String parentPath, long id) {
        String fileName= "publicKeyExported_" + (new Date()).getTime() + ".asc";
        File exportFile = new File(parentPath, fileName);

        try (OutputStream secretOut = new ArmoredOutputStream(new FileOutputStream(exportFile))) {
            PGPPublicKeyRing publicKeyRing = this.getPublicKeyRingForID(id);
            publicKeyRing.encode(secretOut);
            this.openFileLocation(parentPath);
            return true;
        } catch (IOException e) {
            e.printStackTrace();
        }

        return false;
    }

    private void openFileLocation(String path) throws IOException {
        if (Desktop.isDesktopSupported()) {
            Desktop.getDesktop().open(new File(path));
        }
    }

    private PGPPublicKeyRing getPublicKeyRingForID(long idToGet) {
        // Check if it public key from other users
        Iterator<PGPPublicKeyRing> iterator = this.publicKeys.getKeyRings();
        PGPPublicKeyRing publicKeyRing;

        while (iterator.hasNext()) {
            publicKeyRing = iterator.next();
            Iterator<PGPPublicKey> keyIterator = publicKeyRing.getPublicKeys();
            PGPPublicKey masterKey = keyIterator.next();

            // One master key can have multiple sub keys.
            while (keyIterator.hasNext()) {
                PGPPublicKey subKey = keyIterator.next();
                long id = subKey.getKeyID();

                if (id == idToGet) {
                    List<PGPPublicKey> publicKeysList = new LinkedList<>();
                    publicKeysList.add(masterKey);
                    publicKeysList.add(subKey);
                    return new PGPPublicKeyRing(publicKeysList);
                }
            }
        }

        // Check if it is my public key
        PGPSecretKeyRingCollection pgpPrivateKeyRingCollection = this.privateKeys;
        Iterator<PGPSecretKeyRing> iterator2 = pgpPrivateKeyRingCollection.getKeyRings();
        PGPSecretKeyRing secretKeyRing;
        while (iterator2.hasNext())
        {
            secretKeyRing = iterator2.next();
            Iterator<PGPPublicKey> keyIterator = secretKeyRing.getPublicKeys();
            PGPPublicKey masterKey = keyIterator.next();

            while (keyIterator.hasNext()) {
                PGPPublicKey subKey = keyIterator.next();
                long id = subKey.getKeyID();

                if (id == idToGet)
                {
                    List<PGPPublicKey> publicKeysList = new LinkedList<>();
                    publicKeysList.add(masterKey);
                    publicKeysList.add(subKey);
                    return new PGPPublicKeyRing(publicKeysList);
                }
            }
        }
        return null;
    }

    private PGPSecretKey getSecretSubKeyByID(long idToGet) {
        PGPSecretKeyRing secretKeyRing;
        Iterator<PGPSecretKeyRing> iterator = this.privateKeys.getKeyRings();

        while (iterator.hasNext()) {
            secretKeyRing = iterator.next();
            Iterator<PGPSecretKey> keyIterator = secretKeyRing.getSecretKeys();
            PGPSecretKey masterKey = keyIterator.next();

            // One master key can have multiple sub keys.
            while (keyIterator.hasNext()) {
                PGPSecretKey subKey = keyIterator.next();   // returns the key id of the public key (this we need)

                long id = subKey.getKeyID();

                if (id == idToGet) {
                    return subKey;
                }
            }
        }


        return null;
    }

    private PGPSecretKeyRing getSecretKeyRingForID(long idToGet) {
        PGPSecretKeyRing secretKeyRing = null;
        try {
            secretKeyRing = this.privateKeys.getSecretKeyRing(this.getSecretSubKeyByID(idToGet).getKeyID());
        } catch (PGPException e) {
            e.printStackTrace();
        }
        return secretKeyRing;
    }



    public boolean deleteKey(long idToDelete, String password) {
        return password == null ? deletePublicKey(idToDelete) : deletePrivateKey(idToDelete, password);
    }

    private boolean deletePublicKey(long idToDelete) {
        PGPPublicKeyRing publicKeyRing = this.getPublicKeyRingForID(idToDelete);
        if (publicKeyRing == null)
            return false;

        this.publicKeys = this.publicKeys.removePublicKeyRing(this.publicKeys, publicKeyRing);
        this.savePGPPublicKeyRing(null);
        return true;
    }

    private boolean deletePrivateKey(long idToDelete, String passphrase) {
        PGPSecretKey subKey = this.getSecretSubKeyByID(idToDelete);
        if (subKey == null) {
            return false;
        }

        boolean result = this.checkSubKeyWithPassphrase(subKey, passphrase);
        if (!result) {
            return false;
        }

        try {
            this.privateKeys = this.privateKeys.removeSecretKeyRing(this.privateKeys, this.privateKeys.getSecretKeyRing(idToDelete));
        } catch (PGPException e) {
            e.printStackTrace();
        }

        this.savePGPSecretKeyRing(null);

        return true;
    }

    private boolean checkSubKeyWithPassphrase(PGPSecretKey subKey, String passphrase) {
        try {
            subKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase.toCharArray()));
            return true;
        } catch (PGPException e) {
            //e.printStackTrace();
            System.out.println("Lozinka pogresna.");
        }
        return false;
    }
}
