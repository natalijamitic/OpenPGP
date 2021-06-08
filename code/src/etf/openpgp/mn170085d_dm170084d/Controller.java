package etf.openpgp.mn170085d_dm170084d;

import etf.openpgp.mn170085d_dm170084d.keys.KeyGuiVisualisation;
import etf.openpgp.mn170085d_dm170084d.keys.KeyHelper;
import etf.openpgp.mn170085d_dm170084d.keys.KeyReaderWriter;
import etf.openpgp.mn170085d_dm170084d.messaging.MessagingService;
import etf.openpgp.mn170085d_dm170084d.messaging.MessagingUtils;
import javafx.animation.PauseTransition;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;

import java.io.*;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;

import javafx.scene.layout.AnchorPane;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.util.Duration;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

/**
 * Kontroler za GUI Aplikaciju.
 */
public class Controller {
    final String[] generationAlgorithms = {"RSA 1024", "RSA 2048", "RSA 4096"};
    final String[] simetricAlgorithms = {"3DES", "AES 128"};

    @FXML
    private TabPane tabPane;
    @FXML
    private Tab tabKeyView, tabKeyGeneration, tabKeyDeletion, tabImportExport, tabSendMsg, tabReceiveMsg;
    @FXML
    private TextField keyGenerationName, keyGenerationMail, keyGenerationPassword;
    @FXML
    private TextField keyDeletionID, keyDeletionPassword;
    @FXML
    private ChoiceBox<String> keyGenerationAlgorithms, outboxEncryptonAlgorithms;
    @FXML
    private ListView<KeyGuiVisualisation> outboxPublicKeys;
    @FXML
    private Label keyGenerationMsg, keyDeletionMsg;
    @FXML
    private TableView privateKeysTable, publicKeysTable;
    @FXML
    private TableColumn privateKeysTableKeyIDCol, privateKeysTableOwnerIDCol, privateKeysTableTimestampCol, publicKeysTableKeyIDCol, publicKeysTableOwnerIDCol, publicKeysTableTimestampCol;
    @FXML
    private ToggleGroup importKeyType, exportKeyType;
    @FXML
    private TextField exportKeyID, inboxMessagePrivateKey, signatureKeyId, signatureKeyPass;
    @FXML
    private Label importKeyLabel, exportKeyLabel, encryptMessageMsg, inboxMessageInfos, outboxLabel;
    @FXML
    private TextArea importFilePath, exportFilePath, inboxMessagePath, decryptedMessagePath, outboxMessagePath, outboxLocationPath;
    @FXML
    private AnchorPane anchorPaneImportKey, anchorPaneExportKey, anchorPaneReceiveMsg, anchorPaneSendMsg, keyGenerationAnchorPane;
    @FXML
    private DialogPane inboxDialog;
    @FXML
    private CheckBox signatureFlag, encryptonFlag, zipFlag, radixFlag;

    private boolean tabEntered = false;

    private KeyHelper keyHelper;

    /**
     * Inicijalizacija GUI aplikacije.
     */
    public void initialize() {
        // initialization here, if needed...
        System.out.println("init");

        if (keyHelper == null) {
            this.keyHelper = new KeyHelper();
        }

        this.outboxEncryptonAlgorithms.setItems(FXCollections.observableArrayList(simetricAlgorithms));

        this.outboxPublicKeys.setItems(keyHelper.getPublicKeys());
        this.outboxPublicKeys.getSelectionModel().setSelectionMode(SelectionMode.MULTIPLE);

        this.keyGenerationMsg.setText("Hello keyGen World :)");
        this.keyDeletionMsg.setText("Hello keyDel World :)");
        this.keyGenerationAlgorithms.setItems(FXCollections.observableArrayList(generationAlgorithms));
    }

    /**
     * Logika biranja tabova kako bi se znao trenutno aktivni.
     */
    public void tabSelected() {
        tabEntered = !tabEntered;
        if (!tabEntered)            // if we are leaving tab we dont care
            return;
        int selectedTabIndex = this.tabPane.getSelectionModel().getSelectedIndex();
        System.out.println(selectedTabIndex);

        // TODO: refresh selected tab (case 1,2,3...)
        switch (selectedTabIndex) {
            case 0:
                viewKeys();
                break;
            case 3:
                this.importKeyLabel.setText("");
                this.exportKeyLabel.setText("");
                break;
            case 4:
                this.outboxPublicKeys.setItems(keyHelper.getPublicKeys());
                break;
        }
    }

    /**
     * Inicijalizacija pregleda kljuceva.
     */
    private void initializeKeyViewer() {
        this.privateKeysTable.getSelectionModel().setCellSelectionEnabled(true);
        this.publicKeysTable.getSelectionModel().setCellSelectionEnabled(true);
        this.privateKeysTableKeyIDCol.setCellValueFactory(
                new PropertyValueFactory<KeyGuiVisualisation, String>("id")
        );
        this.privateKeysTableOwnerIDCol.setCellValueFactory(
                new PropertyValueFactory<KeyGuiVisualisation, String>("owner")
        );
        this.privateKeysTableTimestampCol.setCellValueFactory(
                new PropertyValueFactory<KeyGuiVisualisation, String>("date")
        );
        this.publicKeysTableKeyIDCol.setCellValueFactory(
                new PropertyValueFactory<KeyGuiVisualisation, String>("id")
        );
        this.publicKeysTableOwnerIDCol.setCellValueFactory(
                new PropertyValueFactory<KeyGuiVisualisation, String>("owner")
        );
        this.publicKeysTableTimestampCol.setCellValueFactory(
                new PropertyValueFactory<KeyGuiVisualisation, String>("date")
        );
    }


    /**********************************************
     *                  KLJUCEVI                  *
     **********************************************/
    /**
     * Pregled kljuceva i privatnih i javnih.
     */
    public void viewKeys() {
        initializeKeyViewer();
        if (keyHelper == null) {
            this.keyHelper = new KeyHelper();
        }

        this.privateKeysTable.setItems(keyHelper.getPrivateKeys());
        this.publicKeysTable.setItems(keyHelper.getPublicKeys());
    }

    /**
     * Generisanje kljuca na osnovu unetih podataka. Poziva se odgovarajuca keyHelper funkcija.
     */
    public void generateKey() {
        this.keyGenerationMsg.setText("Generise se...");

        String name = this.keyGenerationName.getText();
        String mail = this.keyGenerationMail.getText();
        String password = this.keyGenerationPassword.getText();
        String algorithm = this.keyGenerationAlgorithms.getValue(); // NULL if not selected

        if (name.length() == 0 || mail.length() == 0 || password.length() == 0 || algorithm == null) {
            this.keyGenerationMsg.setText("Sva polja su obavezna.");
            return;
        }

        boolean result = this.keyHelper.generateRSAKey(name, mail, password, algorithm);

        PauseTransition delay = new PauseTransition(Duration.seconds(2));
        delay.setOnFinished(event -> this.keyGenerationMsg.setText(result ? "Uspesno generisan kljuc." : "Ups, doslo je do greske."));
        delay.play();
    }

    /**
     * Brisanje kljuca. Poziva se odgovarajuca keyHelper funkcija.
     */
    public void deleteKey() {
        this.keyDeletionMsg.setText("Brise se...");

        String id = this.keyDeletionID.getText();
        String password = this.keyDeletionPassword.getText().length() > 0 ? this.keyDeletionPassword.getText() : null;

        if (id.length() == 0) {
            this.keyDeletionMsg.setText("ID polje je obavezno.");
            return;
        }

        try {
            boolean result = keyHelper.deleteKey(this.stringKeyIdToLong(id), password);
            this.keyDeletionMsg.setText(result ? "Kljuc uspesno obrisan." : "Kljuc nije obrisan.");
        } catch (NumberFormatException e) {
            this.keyDeletionMsg.setText("ID kljuca mora biti broj.");
        }
    }


    /**********************************************
     *                  UVOZ                      *
     **********************************************/
    /**
     * Prozor za biranje uvoznog fajla.
     */
    public void selectImportFile() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Izaberite fajl za uvoz");
        Stage stage = (Stage) anchorPaneImportKey.getScene().getWindow();
        File file = fileChooser.showOpenDialog(stage);
        if (file != null) {
            System.out.println(file.getAbsolutePath());
            this.importFilePath.setText(file.getAbsolutePath());
        } else {
            System.out.println("Fajl je NULL");
            this.importFilePath.setText("");
        }
    }

    /**
     * Uvoz kljuca. Poziva se odgovarajuca keyHelper funkcija.
     */
    public void importKey() {
        this.importKeyLabel.setText("Uvozi se...");

        String filePath = this.importFilePath.getText();
        String keyType = ((RadioButton) importKeyType.getSelectedToggle()).getText();
        System.out.println(filePath + '\n' + keyType);

        if (filePath.length() == 0 || keyType.length() == 0) {
            this.importKeyLabel.setText("Sva polja su obavezna.");
        }
        boolean result = keyType.equals("Privatni") ? this.keyHelper.importPrivateKey(filePath) : this.keyHelper.importPublicKey(filePath);
        System.out.println("OVDE");
        System.out.println(result);
        this.importKeyLabel.setText(result ? "Uspesan uvoz." : "Ups, doslo je do greske. Verovatno vec postoji kljuc sa tim IDijem.");

        PauseTransition delay = new PauseTransition(Duration.seconds(2));
        delay.setOnFinished(event -> this.importKeyLabel.setText(""));
        delay.play();
    }


    /**********************************************
     *                  IZVOZ                     *
     **********************************************/
    /**
     * Prozor za biranje izvoznog fajla.
     */
    public void selectExportFile() {
        System.out.println("select export file");

        DirectoryChooser directoryChooser = new DirectoryChooser();
        directoryChooser.setTitle("Izaberite direktorijum za izvoz");
        Stage stage = (Stage) anchorPaneExportKey.getScene().getWindow();
        File file = directoryChooser.showDialog(stage);
        if (file != null) {
            System.out.println(file.getAbsolutePath());
            this.exportFilePath.setText(file.getAbsolutePath());
        } else {
            System.out.println("Fajl je NULL");
            this.exportFilePath.setText("");
        }
    }

    /**
     * Izvoz kljuca. Poziva se odgovarajuca keyHelper funkcija.
     */
    public void exportKey() {
        this.exportKeyLabel.setText("Izvozi se..");

        String keyId = this.exportKeyID.getText();
        String filePath = this.exportFilePath.getText();
        String keyType = ((RadioButton) exportKeyType.getSelectedToggle()).getText();
        System.out.println(filePath + '\n' + keyType + " " + keyId);
        if (keyId.length() == 0 || filePath.length() == 0 || keyType.length() == 0) {
            this.exportKeyLabel.setText("Sva polja su obavezna.");
        }

        boolean result = keyType.equals("Privatni") ? this.keyHelper.exportPrivateKey(filePath, this.stringKeyIdToLong(keyId)) : this.keyHelper.exportPublicKey(filePath, this.stringKeyIdToLong(keyId));
        this.exportKeyLabel.setText(result ? "Uspesan izvoz." : "Ups, doslo je do greske.");

        PauseTransition delay = new PauseTransition(Duration.seconds(2));
        delay.setOnFinished(event -> this.exportKeyLabel.setText(""));
        delay.play();
    }


    /**********************************************
     *                  PRIJEM                    *
     **********************************************/
    /**
     * Prozor za biranje prijemne poruke.
     */
    public void selectInboxMessage() {
        System.out.println("select inbox message");

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Izaberite kriptovanu prijemnu poruku");
        Stage stage = (Stage) anchorPaneReceiveMsg.getScene().getWindow();
        File file = fileChooser.showOpenDialog(stage);
        if (file != null) {
            System.out.println(file.getAbsolutePath());
            this.inboxMessagePath.setText(file.getAbsolutePath());
        } else {
            System.out.println("Fajl je NULL");
            this.inboxMessagePath.setText("");
        }
    }

    /**
     * Prozor za biranje lokacije dekriptovane poruke.
     */
    public void selectDecryptedMessage() {
        System.out.println("select decrypt inbox message directory");

        DirectoryChooser directoryChooser = new DirectoryChooser();
        directoryChooser.setTitle("Izaberite direktorijum za dekriptovanu poruku");
        Stage stage = (Stage) anchorPaneReceiveMsg.getScene().getWindow();
        File file = directoryChooser.showDialog(stage);
        if (file != null) {
            System.out.println(file.getAbsolutePath());
            this.decryptedMessagePath.setText(file.getAbsolutePath());
        } else {
            System.out.println("Fajl je NULL");
            this.decryptedMessagePath.setText("");
        }
    }

    /**
     * Metoda koja predstavlja hendler koji se zove prilikom prijema poruke.
     * Hendler dohvata poruku koja je enkriptovana, ucitava fajl, vrsi odgovarajuce
     * provere da li podaci treba da se dekriptuju, dekoduju iz radix64 itd. i cuva
     * dekriptovanu poruku. Ukoliko ne uspe u tome ispisuje odgovarajucu poruku o gresci.
     */
    public void receiveMessage() {
        String srcPath = this.inboxMessagePath.getText();
        FileInputStream fileStream = null;
        byte[] data = null;
        try {
            fileStream = new FileInputStream(srcPath);
            data = fileStream.readAllBytes();
            fileStream.close();
        } catch (FileNotFoundException e) {
            encryptMessageMsg.setText("Greska pri otvaranju fajla");
            return;
        } catch (IOException e) {
            encryptMessageMsg.setText("Greska pri citanju fajla");
            return;
        }

        byte[] decodedRadix = null;
        byte[] decryptedData = null;
        byte[] unzippedData = null;
        boolean verified = false;
        byte[] message = null;

        try {
            decodedRadix = MessagingService.decodeArmoredStream(data);
        } catch(Exception e)
        {
            decodedRadix = data;
        }

        if(MessagingService.isDataEncrypted(decodedRadix))
        {
            PasswordPrompt prompt = new PasswordPrompt(this.outboxLabel.getScene().getWindow());
            String encryptionPassword = prompt.getResult();
            System.out.println(encryptionPassword);

            try {
                JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(decodedRadix);
                Object object= objectFactory.nextObject();

                if(object instanceof PGPEncryptedDataList)
                {
                    PGPEncryptedDataList edl = (PGPEncryptedDataList) object;
                    Iterator<PGPEncryptedData> encryptedDataObjects = edl.getEncryptedDataObjects();
                    PGPPublicKeyEncryptedData encryptedData = (PGPPublicKeyEncryptedData) encryptedDataObjects.next();

                    // IZMENA
                    PGPSecretKey secretKey = keyHelper.getAnySecretKeyById(encryptedData.getKeyID()); // keyHelper.getSecretKeyById(encryptedData.getKeyID());
                    if (secretKey == null){
                        encryptMessageMsg.setText("Greska pri dekripciji. Nije za Vas enkriptovana poruka.");
                        return;
                    }
                    PGPPrivateKey privateKey = secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
                            .setProvider("BC").build(encryptionPassword.toCharArray()));

                    decryptedData = MessagingService.decrypt(decodedRadix, privateKey);

                    new TextPrompt(this.outboxLabel.getScene().getWindow(), "Uspesno dekriptovana poruka.");
                } else
                {
                    encryptMessageMsg.setText("Greska pri dekripciji 1");
                    return;
                }
            } catch (IOException e) {
                encryptMessageMsg.setText("Greska pri dekripciji 2");
                return;
            } catch (PGPException e) {
                encryptMessageMsg.setText("Greska pri dekripciji - pogresna lozinka");
                return;
            } catch (Exception e) {
                encryptMessageMsg.setText("Greska pri dekripciji 3");
                return;
            }
        } else
        {
            decryptedData = decodedRadix;
        }

        try {
            unzippedData = MessagingService.unzip(decryptedData);
            new TextPrompt(this.outboxLabel.getScene().getWindow(), "Uspesno unzippovana poruka.");
        } catch(Exception e)
        {
            unzippedData = decryptedData;
        }

        if(MessagingService.isDataSigned(unzippedData))
        {
            // Izvuci keyID iz potpisa i dohvati javni kljuc
            JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(unzippedData);
            Object o = null;
            try {
                o = objectFactory.nextObject();
            } catch (IOException e) {
                e.printStackTrace();
            }
            long signatureKeyId = -1;
            if(o instanceof PGPOnePassSignatureList)
            {
                PGPOnePassSignatureList sl = (PGPOnePassSignatureList) o;
                PGPOnePassSignature signature = sl.get(0);
                signatureKeyId = signature.getKeyID();
            }

            PGPPublicKeyRing publicKeyRing = keyHelper.getPublicKeyRingById(signatureKeyId);

            // IZMENA
            PGPPublicKey verifyingKey = this.keyHelper.extractMasterPublicKey(publicKeyRing); // keyHelper.extractPublicKey(publicKeyRing);

            try {
                verified = MessagingService.verifySignature(unzippedData, verifyingKey);
            } catch (IOException e) {
                encryptMessageMsg.setText("Greska pri verifikaciji potpisa");
                return;
            } catch (PGPException e) {
                encryptMessageMsg.setText("Greska pri verifikaciji potpisa");
                return;
            }
            if(verified) {
                new TextPrompt(this.outboxLabel.getScene().getWindow(), "Uspesno verifikovan potpis od " + verifyingKey.getUserIDs().next());
                System.out.println("Potpis je verifikovan");
            } else
                System.out.println("Potpis nije verifikovan");
            try {
                message = MessagingService.readSignedMessage(unzippedData);
            } catch (IOException e) {
                encryptMessageMsg.setText("Greska pri citanju originalne poruke");
                return;
            }
        } else {
            System.out.println("Poruka nije potpisana");
            message = unzippedData;
            if(message[0] == -53 && message[5] == -69)
            {
                message = Arrays.copyOfRange(message, 8, message.length);
            }
        }

        String dstPath = decryptedMessagePath.getText() + "/" + "decryptedMessage_" + (new Date()).getTime() + ".gpg";
        try {
            FileOutputStream outputStream = new FileOutputStream(dstPath);
            outputStream.write(message);
            outputStream.close();
            encryptMessageMsg.setText("Poruka je uspesno desifrovana");
        } catch (FileNotFoundException e) {
            encryptMessageMsg.setText("Greska pri cuvanju dekriptovane poruke");
            return;
        } catch (IOException e) {
            encryptMessageMsg.setText("Greska pri cuvanju dekriptovane poruke");
            return;
        }

    }

    /**
     * Unos sifre za dekriptovanje poruke.
     */
    public void checkInboxMessagePrivateKey() {
        System.out.println("enter pass for decrypting inbox message");
        String privateKey = this.inboxMessagePrivateKey.getText();
        this.inboxMessageInfos.setText("obradjuje se privatni kljuc");

        PauseTransition delay1 = new PauseTransition(Duration.seconds(1));
        delay1.setOnFinished(event -> this.inboxMessageInfos.setText("obradjeno, gasimo prozor"));
        delay1.play();

        PauseTransition delay2 = new PauseTransition(Duration.seconds(2));
        delay2.setOnFinished(event -> {
            this.inboxDialog.setVisible(false);
            this.inboxMessageInfos.setText("");
        });
        delay2.play();
    }

    /**
     * Zatvaranje dijaloga za unos lozinke.
     */
    public void closeInboxDialog() {
        this.inboxDialog.setVisible(false);
    }


    /**********************************************
     *                  SLANJE                    *
     **********************************************/
    /**
     * Brisanje unetih podataka iz prozora za slanje poruke.
     */
    private void clearSendScreen() {
        outboxMessagePath.clear();
        outboxLocationPath.clear();
        signatureFlag.setSelected(false);
        signatureKeyPass.clear();
        signatureKeyId.clear();
        outboxLabel.setText("");
        encryptonFlag.setSelected(false);
        outboxEncryptonAlgorithms.getSelectionModel().clearSelection();
        zipFlag.setSelected(false);
        radixFlag.setSelected(false);
    }

    /**
     * Metoda koja predstavlja hendler koji se poziva kada korisnik salje poruku.
     * Hendler dohvata sve neophodne podatke iz forme, verifikuje ih i salje poruku
     * ako su ispravni. Ako nisu ispravni ispisuje poruku o odgovarajucoj gresci.
     */
    public void sendMessage() {
        //srcPath, dstPath, isSigned, signingKey
        String srcPath = outboxMessagePath.getText();
        String dstPath = outboxLocationPath.getText();

        boolean isSigned = signatureFlag.isSelected();
        long signedKeyId = 0;
        PGPPrivateKey signingKey = null;
        String signatureKeyPassword = signatureKeyPass.getText();
        int signingAlgorithm = -1;
        if (isSigned) {
            if (signatureKeyId.getText().length() == 0 || signatureKeyPassword.length() == 0) {
                outboxLabel.setText("Za izabrano potpisivanje nisu popunjena sva polja.");
                return;
            }
            signedKeyId = this.stringKeyIdToLong(signatureKeyId.getText());
            // IZMENA
            PGPSecretKey secretKey = this.keyHelper.getMasterSecreyKeyBySubKeyId(signedKeyId);// this.keyHelper.getSecretKeyById(signedKeyId);
            try {
                signingKey = secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(signatureKeyPassword.toCharArray()));
                signingAlgorithm = secretKey.getPublicKey().getAlgorithm();
                System.out.println("ALGO: " + signingAlgorithm);
            } catch (PGPException e) {
                outboxLabel.setText("Pogresna sifra privatnog kljuca za potpisivanje");
                return;
            }
        }

        boolean isEncrypted = encryptonFlag.isSelected();
        String encryptionAlgo = this.outboxEncryptonAlgorithms.getSelectionModel().getSelectedItem();
        if (isEncrypted && (encryptionAlgo == null || encryptionAlgo.length() == 0)) {
            outboxLabel.setText("Za izabranu enkripciju nisu popunjena sva polja.");
            return;
        }
        int encryptionAlgorithm = -1;
        if("3DES".equals(encryptionAlgo))
            encryptionAlgorithm = SymmetricKeyAlgorithmTags.TRIPLE_DES;
        else
            encryptionAlgorithm = SymmetricKeyAlgorithmTags.AES_128;
        ObservableList<KeyGuiVisualisation> pubKeys = this.outboxPublicKeys.getSelectionModel().getSelectedItems();
        if (isEncrypted && (pubKeys == null || pubKeys.size() == 0)) {
            outboxLabel.setText("Za izabranu enkripciju nisu popunjena sva polja.");
            return;
        }
        PGPPublicKeyRing publicKeyRing = null;
        PGPPublicKey publicKey = null;
        boolean isZipped = zipFlag.isSelected();
        boolean isRadix = radixFlag.isSelected();
        if(isEncrypted)
        {
            for(KeyGuiVisualisation keyGui : pubKeys)
            {
                long pubKeyId = keyGui.stringKeyIdToLong(keyGui.getId());
                publicKeyRing = this.keyHelper.getPublicKeyRingById(pubKeyId);
                publicKey = this.keyHelper.extractPublicKey(publicKeyRing);
                MessagingUtils.sendMessage(srcPath, dstPath, isSigned, signingKey, signingAlgorithm, isEncrypted, publicKey, encryptionAlgorithm, isZipped, isRadix);
                outboxLabel.setText("Poruka je uspesno poslata");
                clearSendScreen();
            }
        } else
        {
            MessagingUtils.sendMessage(srcPath, dstPath, isSigned, signingKey, signingAlgorithm, false, null, -1, isZipped, isRadix);
            outboxLabel.setText("Poruka je uspesno poslata");
            clearSendScreen();
        }

        System.out.println(srcPath + " " + dstPath + " " + isSigned + " " + signedKeyId + " " + signatureKeyPassword + " " + isEncrypted + " " + encryptionAlgo + " " + pubKeys + " " + isZipped + " " + isRadix);
    }

    /**
     * Prozor za biranje poruke koja se salje.
     */
    public void selectOutboxMessage() {
        System.out.println("select outbox message");

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Izaberite poruku za slanje.");
        Stage stage = (Stage) anchorPaneSendMsg.getScene().getWindow();
        File file = fileChooser.showOpenDialog(stage);
        if (file != null) {
            System.out.println(file.getAbsolutePath());
            this.outboxMessagePath.setText(file.getAbsolutePath());
        } else {
            System.out.println("Fajl je NULL");
            this.outboxMessagePath.setText("");
        }
    }

    /**
     * Prozor za biranje lokacije na koju se salje.
     */
    public void selectOutboxLocation() {
        DirectoryChooser directoryChooser = new DirectoryChooser();
        directoryChooser.setTitle("Izaberite direktorijum za slanje poruke");
        Stage stage = (Stage) anchorPaneSendMsg.getScene().getWindow();
        File file = directoryChooser.showDialog(stage);
        if (file != null) {
            System.out.println(file.getAbsolutePath());
            this.outboxLocationPath.setText(file.getAbsolutePath());
        } else {
            System.out.println("Fajl je NULL");
            this.outboxLocationPath.setText("");
        }
    }

    /**********************************************
     *                  HELPERI                   *
     **********************************************/

    /**
     * Konverzija stringa u long.
     * @param keyId
     * @return Long vrednost stringa.
     */
    private long stringKeyIdToLong(String keyId) {
        return Long.parseUnsignedLong(keyId, 16);
    }

    /**
     * Incijalizacija tabela - dodavanje hendlera.
     */
    public void initializeApp() {
        TableUtils.installCopyPasteHandler(this.privateKeysTable);
        TableUtils.installCopyPasteHandler(this.publicKeysTable);

        TableUtils.installContextMenu(this.privateKeysTable);
        TableUtils.installContextMenu(this.publicKeysTable);
    }
}
