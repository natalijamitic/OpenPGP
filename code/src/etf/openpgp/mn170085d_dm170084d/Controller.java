package etf.openpgp.mn170085d_dm170084d;

import etf.openpgp.mn170085d_dm170084d.keys.KeyGuiVisualisation;
import etf.openpgp.mn170085d_dm170084d.keys.KeyHelper;
import javafx.animation.PauseTransition;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;

import java.io.File;

import javafx.scene.layout.AnchorPane;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.util.Duration;

public class Controller {
    final String[] generationAlgorithms = {"RSA 1024", "RSA 2048", "RSA 4096"};
    final String[] simetricAlgorithms = {"3DES + EDE", "AES 128"};

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

    // gets called for leaving + entering
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
    public void viewKeys() {
        initializeKeyViewer();
        if (keyHelper == null) {
            this.keyHelper = new KeyHelper();
        }

        this.privateKeysTable.setItems(keyHelper.getPrivateKeys());
        this.publicKeysTable.setItems(keyHelper.getPublicKeys());
    }

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

    public void importKey() {
        this.importKeyLabel.setText("Uvozi se...");

        String filePath = this.importFilePath.getText();
        String keyType = ((RadioButton) importKeyType.getSelectedToggle()).getText();
        System.out.println(filePath + '\n' + keyType);

        if (filePath.length() == 0 || keyType.length() == 0) {
            this.importKeyLabel.setText("Sva polja su obavezna.");
        }
        boolean result = keyType.equals("Privatni") ? this.keyHelper.importPrivateKey(filePath) : this.keyHelper.importPublicKey(filePath);
        this.importKeyLabel.setText(result ? "Uspesan uvoz." : "Ups, doslo je do greske.");

        PauseTransition delay = new PauseTransition(Duration.seconds(2));
        delay.setOnFinished(event -> this.importKeyLabel.setText(""));
        delay.play();
    }


    /**********************************************
     *                  IZVOZ                     *
     **********************************************/
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

    public void selectDecryptedMessage() {
        System.out.println("select decrypt inbox message directory");

        DirectoryChooser directoryChooser = new DirectoryChooser();
        directoryChooser.setTitle("Izaberite direktorijum za enkriptovanu poruku");
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

    public void receiveMessage() {
        System.out.println("decrypt received Message");
        this.encryptMessageMsg.setText("U toku je obrada primljene poruke..");
        this.inboxDialog.setVisible(true);
    }

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

    public void closeInboxDialog() {
        this.inboxDialog.setVisible(false);
    }


    /**********************************************
     *                  SLANJE                    *
     **********************************************/
    public void sendMessage() {
        String msgPath = outboxMessagePath.getText();
        String deliveryPath = outboxLocationPath.getText();

        boolean isSignature = signatureFlag.isSelected();
        long keyId = 0;
        String keyPass = signatureKeyPass.getText();
        if (isSignature) {
            if (signatureKeyId.getText().length() == 0 || keyPass.length() == 0) {
                outboxLabel.setText("Za izabrano potpisivanje nisu popunjena sva polja.");
                return;
            }
            keyId = this.stringKeyIdToLong(signatureKeyId.getText());
        }

        boolean isEncrypton = encryptonFlag.isSelected();
        String encryptionAlgo = this.outboxEncryptonAlgorithms.getSelectionModel().getSelectedItem();
        if (isEncrypton && encryptionAlgo == null) {
            outboxLabel.setText("Za izabranu enkripciju nisu popunjena sva polja.");
            return;
        }
        ObservableList<KeyGuiVisualisation> pubKeys = this.outboxPublicKeys.getSelectionModel().getSelectedItems();

        boolean isZip = zipFlag.isSelected();
        boolean isRadix = radixFlag.isSelected();

        System.out.println(msgPath + " " + deliveryPath + " " + isSignature + " " + keyId + " " + keyPass + " " + isEncrypton + " " + encryptionAlgo + " " + pubKeys + " " + isZip + " " + isRadix);
    }

    public void selectOutboxMessage() {
        System.out.println("select outbox message");

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Izaberite prijemnu poruku za sifrovanje");
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

    private long stringKeyIdToLong(String keyId) {
        return Long.parseUnsignedLong(keyId, 16);
    }

    public void initializeApp() {
        TableUtils.installCopyPasteHandler(this.privateKeysTable);
        TableUtils.installCopyPasteHandler(this.publicKeysTable);

        TableUtils.installContextMenu(this.privateKeysTable);
        TableUtils.installContextMenu(this.publicKeysTable);
    }
}
