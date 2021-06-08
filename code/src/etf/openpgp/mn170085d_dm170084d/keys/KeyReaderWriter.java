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

/**
 * Klasa namenjena za osnovne manipulacije (citanje, upis, brisanje) nad kljucevima.
 */
public class KeyReaderWriter {
    private PGPSecretKeyRingCollection privateKeys;
    private PGPPublicKeyRingCollection publicKeys;

    /**
     * Citanje kljuceva, kako javnih tako i privatnih, iz odgovarajucih fajlova.
     */
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

    /**
     * Cuvanje privatnog prstena kljuceva lokalno i u fajl.
     * @param secretKeyRing Prsten koji se cuva
     * @return uspesnost operacije
     */
    public boolean savePGPSecretKeyRing(PGPSecretKeyRing secretKeyRing) {
        try (OutputStream secretOut = new ArmoredOutputStream(new FileOutputStream(Globals.privateKeysPath))) {
            if (secretKeyRing != null) {
                this.privateKeys = PGPSecretKeyRingCollection.addSecretKeyRing(this.privateKeys, secretKeyRing);
            }
            this.privateKeys.encode(secretOut);
            return true;
        } catch (IllegalArgumentException e) {
            System.out.println("duplo");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        this.savePGPPublicKeyRing(null);
        return false;
    }

    /**
     * Cuvanje privatnog prstena kljuceva lokalno i u fajl.
     * @param publicKeyRing Prsten koji se cuva
     * @return uspesnost operacije.
     */
    public boolean savePGPPublicKeyRing(PGPPublicKeyRing publicKeyRing) {
        try (OutputStream secretOut = new ArmoredOutputStream(new FileOutputStream(Globals.publicKeysPath))) {
            if (publicKeyRing != null) {
                this.publicKeys = PGPPublicKeyRingCollection.addPublicKeyRing(this.publicKeys, publicKeyRing);
            }
            this.publicKeys.encode(secretOut);
            System.out.println("sacuvano");
            return true;
        } catch (IllegalArgumentException e) {
            System.out.println("duplo");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        this.savePGPPublicKeyRing(null);
        return false;
    }

    /**
     * Dohvatanje privatnih kljuceva.
     * @return lista privatnih kljuceva
     */
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

    /**
     * Dohvatanje javnih kljuceva.
     * @return lista javnih kljuceva.
     */
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

    /**
     * Uvoz privatnog kljuca sa lokacije.
     * @param path
     * @return uspesnost operacije.
     */
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

    /**
     * Uvoz javnog kljuca sa lokacije.
     * @param path
     * @return uspesnost operacije.
     */
    public boolean importPublicKey(String path) {
        try (InputStream inputStream = new ArmoredInputStream(new FileInputStream(path))) {
            PGPPublicKeyRing publicKeyRing = new PGPPublicKeyRing(inputStream, new JcaKeyFingerprintCalculator());
            return this.savePGPPublicKeyRing(publicKeyRing);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return false;
    }

    /**
     * Izvoz privatnog kljuca na lokaciju.
     * @param parentPath
     * @param id ID kljuca koji se izvozi
     * @param passphrase Sifra pod kojom se cuva taj kljuc
     * @return uspesnost operacije.
     */
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

        String fileName = "privateKeyExported_" + (new Date()).getTime() + ".asc";
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

    /**
     * Izvoz javnog kljuca na lokaciju
     * @param parentPath
     * @param id ID kljuca koji se izvozi
     * @return uspesnost operacije.
     */
    public boolean exportPublicKey(String parentPath, long id) {
        String fileName = "publicKeyExported_" + (new Date()).getTime() + ".asc";
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

    /**
     * Otvaranje lokacije.
     * @param path
     * @throws IOException
     */
    private void openFileLocation(String path) throws IOException {
        if (Desktop.isDesktopSupported()) {
//            Desktop.getDesktop().open(new File(path));
        }
    }

    /**
     * Dohvatanje prsetna javnih kljuceva na osnovu IDija (bilo master ili sub kljuca)
     * @param idToGet
     * @return prsten javnih kljuceva
     */
    public PGPPublicKeyRing getPublicKeyRingForID(long idToGet) {
        // Check if it public key from other users
        Iterator<PGPPublicKeyRing> iterator = this.publicKeys.getKeyRings();
        PGPPublicKeyRing publicKeyRing;

        while (iterator.hasNext()) {
            publicKeyRing = iterator.next();
            Iterator<PGPPublicKey> keyIterator = publicKeyRing.getPublicKeys();
            PGPPublicKey masterKey = keyIterator.next();

            // za kleopatru provera
            if (masterKey.getKeyID() == idToGet) {
                List<PGPPublicKey> publicKeysList = new LinkedList<>();
                publicKeysList.add(masterKey);
                publicKeysList.add(keyIterator.next());
                return new PGPPublicKeyRing(publicKeysList);
            }

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
        while (iterator2.hasNext()) {
            secretKeyRing = iterator2.next();
            Iterator<PGPPublicKey> keyIterator = secretKeyRing.getPublicKeys();
            PGPPublicKey masterKey = keyIterator.next();

            // za kleopatru provera
            if (masterKey.getKeyID() == idToGet) {
                List<PGPPublicKey> publicKeysList = new LinkedList<>();
                publicKeysList.add(masterKey);
                publicKeysList.add(keyIterator.next());
                return new PGPPublicKeyRing(publicKeysList);
            }

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
        return null;
    }

    /**
     * Dohvatanje tajnog sub kljuca na osnovu IDija.
     * @param idToGet
     * @return tajni kljuc
     */
    public PGPSecretKey getSecretSubKeyByID(long idToGet) {
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

    /**
     * Dohvatanje tajnog kljuca na osnovu IDija bilo master ili sub kljuca.
     * @param idToGet
     * @return tajni kljuc.
     */
    public PGPSecretKey getAnySecretKeyById(long idToGet) {
        PGPSecretKeyRing secretKeyRing;
        Iterator<PGPSecretKeyRing> iterator = this.privateKeys.getKeyRings();

        while (iterator.hasNext()) {
            secretKeyRing = iterator.next();
            Iterator<PGPSecretKey> keyIterator = secretKeyRing.getSecretKeys();
            PGPSecretKey masterKey = keyIterator.next();

            if (masterKey.getKeyID() == idToGet) {
                return masterKey;
            }
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

    /**
     * Dohvatanje tajnog master kljuca na osnovu IDija sub kljuca.
     * @param idToGet ID sub kljuca.
     * @return tajni master kljuc.
     */
    public PGPSecretKey getSecretMasterKeyBySubKeyId(long idToGet) {
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
                    return masterKey;
                }
            }
        }


        return null;
    }

    /**
     * Dohvatanje tajnog master kljuca na osnovu IDija master kljuca.
     * @param idToGet ID master kljuca
     * @return tajni master kljuc.
     */
    public PGPSecretKey getSecretMasterKeyByMasterKeyId(long idToGet) {
        PGPSecretKeyRing secretKeyRing;
        Iterator<PGPSecretKeyRing> iterator = this.privateKeys.getKeyRings();

        while (iterator.hasNext()) {
            secretKeyRing = iterator.next();
            Iterator<PGPSecretKey> keyIterator = secretKeyRing.getSecretKeys();
            PGPSecretKey masterKey = keyIterator.next();

            if (masterKey.getKeyID() == idToGet) {
                return masterKey;
            }

        }

        return null;
    }

    /**
     * Dohvatanje tajnog prstena kljuceva na osnovu IDija.
     * @param idToGet
     * @return prsten tajnih kljuceva
     */
    private PGPSecretKeyRing getSecretKeyRingForID(long idToGet) {
        PGPSecretKeyRing secretKeyRing = null;
        try {
            secretKeyRing = this.privateKeys.getSecretKeyRing(this.getSecretSubKeyByID(idToGet).getKeyID());
        } catch (PGPException e) {
            e.printStackTrace();
        }
        return secretKeyRing;
    }


    /**
     * Brisanje kljuca na osnovu IDija i sifre.
     * @param idToDelete
     * @param password
     * @return uspesnost operacije
     */
    public boolean deleteKey(long idToDelete, String password) {
        return password == null ? deletePublicKey(idToDelete) : deletePrivateKey(idToDelete, password);
    }

    /**
     * Brisanje javnog kljuca
     * @param idToDelete
     * @return uspesnost operacije
     */
    private boolean deletePublicKey(long idToDelete) {
        PGPPublicKeyRing publicKeyRing = this.getPublicKeyRingForID(idToDelete);
        if (publicKeyRing == null)
            return false;

        this.publicKeys = this.publicKeys.removePublicKeyRing(this.publicKeys, publicKeyRing);
        this.savePGPPublicKeyRing(null);
        return true;
    }

    /**
     * Brisanje privatnog kljuca
     * @param idToDelete
     * @param passphrase Sifra pod kojom se cuva kljuc.
     * @return uspesnost operacije
     */
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

    /**
     * Provera da li sifra odgovara privatnom kljucu.
     * @param subKey Privatni kljuc
     * @param passphrase Sifra
     * @return uspesnost operacije
     */
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
