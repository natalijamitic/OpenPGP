package etf.openpgp.mn170085d_dm170084d.keys;

import javafx.collections.ObservableList;
import org.bouncycastle.openpgp.*;

import java.util.Iterator;

/**
 * Pomocna (wrapper) klasa koja je zaduzena za sve funkcionalnosti koje se ticu kljuceva.
 */
public class KeyHelper {
    /**
     * Objekat zaduzen za osnovne operacije nad kljucevima (upis, citanje, brisanje).
     */
    private KeyReaderWriter keyReaderWriter;
    /**
     * Objekat zaduzen za generisanje kljuceva.
     */
    private KeyGenerator keyGenerator;

    /**
     * Inicijalizacija prilikom koje se ucitavaju zapamceni kljucevi.
     */
    public KeyHelper() {
        this.keyGenerator = new KeyGenerator();
        this.keyReaderWriter = new KeyReaderWriter();
        this.keyReaderWriter.readKeys();
    }

    /**
     * Pravljenje kljuca RSA algoritmom.
     * @param name Ime osobe za koju se pravi kljuc.
     * @param mail Mail osobe za koju se pravi kljuc.
     * @param passphrase Sifra pod kojom se pravi kljuc.
     * @param algorithm Vrsta (velicina kljuca) RSA algoritma.
     * @return true za uspesno napravljen kljuc, inace false.
     */
    public boolean generateRSAKey(String name, String mail, String passphrase, String algorithm) {
        String identity = name + " <" + mail + ">";
        int keySize = Integer.parseInt(algorithm.substring(4));

        PGPSecretKeyRing secretKeyRing = this.keyGenerator.generateRSAPGPSecretKeyRing(identity, passphrase, keySize);

        return this.keyReaderWriter.savePGPSecretKeyRing(secretKeyRing);
    }

    /**
     * Dohvatanje liste privatnih (licnih) kjuceva.
     * @return Lista
     */
    public ObservableList<KeyGuiVisualisation> getPrivateKeys() {
        return this.keyReaderWriter.getPrivateKeys();
    }

    /**
     * Dohvatanje liste javnih (tudjih) kjuceva.
     * @return Lista
     */
    public ObservableList<KeyGuiVisualisation> getPublicKeys() {
        return this.keyReaderWriter.getPublicKeys();
    }

    /**
     * Brisanje kljuca na osnovu javnog IDija i sifre.
     * @param id
     * @param password
     * @return true za uspesno obrisan kljuc, inace false.
     */
    public boolean deleteKey(long id, String password) {
        return this.keyReaderWriter.deleteKey(id, password);
    }

    /**
     * Izvoz privatnog kljuca na datu lokaciju.
     * @param filePath Lokacija gde se izvozi kljuc.
     * @param id ID kljuca koji se izvozi.
     * @return true za uspesno izvrsavanje, inace false.
     */
    public boolean exportPrivateKey(String filePath, long id) {
        return this.keyReaderWriter.exportPrivateKey(filePath, id, null);
    }

    /**
     * Izvoz javnog kljuca na datu lokaciju.
     * @param filePath Lokacija gde se izvozi kljuc.
     * @param id ID kljuca koji se izvozi.
     * @return true za uspesno izvrsavanje, inace false.
     */
    public boolean exportPublicKey(String filePath, long id) {
        return this.keyReaderWriter.exportPublicKey(filePath, id);
    }

    /**
     * Uvoz privatnog kljuca na datu lokaciju.
     * @param filePath Lokacija odakle se uvozi kljuc.
     * @return true za uspesno izvrsavanje, inace false.
     */
    public boolean importPrivateKey(String filePath) {
        return this.keyReaderWriter.importPrivateKey(filePath);
    }

    /**
     * Uvoz javnog kljuca na datu lokaciju.
     * @param filePath Lokacija odakle se uvozi kljuc.
     * @return true za uspesno izvrsavanje, inace false.
     */
    public boolean importPublicKey(String filePath) {
        return this.keyReaderWriter.importPublicKey(filePath);
    }

    /**
     * Dohvatanje javnog prstena kljuceva na osnovu IDija (bilo master ili subkljuca).
     * @param Id
     * @return prsten javnih kljuceva
     */
    public PGPPublicKeyRing getPublicKeyRingById(long Id)
    {
        return this.keyReaderWriter.getPublicKeyRingForID(Id);
    }

    /**
     * Dohvatanje tajnog kljuca na osnovu IDija.
     * @param Id
     * @return tajni kljuc.
     */
    public PGPSecretKey getSecretKeyById(long Id)
    {
        PGPSecretKey secretKey = this.keyReaderWriter.getSecretSubKeyByID(Id);
        return secretKey;
    }

    /**
     * Dohvatanje tajnog kljuca (bilo master ili sub) na osnovu IDija.
     * @param Id
     * @return tajni kljuc.
     */
    public PGPSecretKey getAnySecretKeyById(long Id) {
        return this.keyReaderWriter.getAnySecretKeyById(Id);
    }

    /**
     * Dohvatanje tajnog master kljuca na osnovu IDija sub kljuca.
     * @param Id sub kljuca
     * @return tajni master kljuc
     */
    public PGPSecretKey getMasterSecreyKeyBySubKeyId(long Id) {
        PGPSecretKey secretSubKey = this.keyReaderWriter.getSecretMasterKeyBySubKeyId(Id);
        return secretSubKey;
    }

    /**
     * Dohvatanje tajnog master kljuca na osnovu IDija master kljuca.
     * @param Id master kljuca
     * @return tajni master kljuc
     */
    public PGPSecretKey getMasterSecretKeyByMasterKeyId(long Id) {
        return this.keyReaderWriter.getSecretMasterKeyByMasterKeyId(Id);
    }

    /**
     * Izvlacenje javnog sub kljuca iz prstena javnih kljuceva.
     * @param publicKeyRing
     * @return javni sub kljuc
     */
    public PGPPublicKey extractPublicKey(PGPPublicKeyRing publicKeyRing)
    {
        Iterator<PGPPublicKey> publicKeys = publicKeyRing.getPublicKeys();
        PGPPublicKey publicKey = publicKeys.next();
        publicKey = publicKeys.next();
        return publicKey;
    }

    /**
     * Izvlacenje javnog master kljuca iz prstena javnih kljuceva.
     * @param publicKeyRing
     * @return javni master kljuc
     */
    public PGPPublicKey extractMasterPublicKey(PGPPublicKeyRing publicKeyRing)
    {
        Iterator<PGPPublicKey> publicKeys = publicKeyRing.getPublicKeys();
        return publicKeys.next();
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
