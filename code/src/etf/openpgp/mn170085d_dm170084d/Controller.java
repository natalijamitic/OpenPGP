package etf.openpgp.mn170085d_dm170084d;

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

    @FXML
    private TabPane tabPane;
    @FXML
    private Tab tabKeyView, tabKeyGeneration, tabKeyDeletion, tabImportExport, tabSendMsg, tabReceiveMsg;
    @FXML
    private TextField keyGenerationName, keyGenerationMail, keyGenerationPassword;
    @FXML
    private TextField keyDeletionID, keyDeletionPassword;
    @FXML
    private ChoiceBox<String> keyGenerationAlgorithms;
    @FXML
    private Label keyGenerationMsg, keyDeletionMsg;
    @FXML
    private TableView privateKeysTable, publicKeysTable;
    @FXML
    private TableColumn privateKeysTableKeyIDCol, privateKeysTableOwnerIDCol, privateKeysTableTimestampCol, publicKeysTableKeyIDCol, publicKeysTableOwnerIDCol, publicKeysTableTimestampCol;

    @FXML
    private ToggleGroup importKeyType, exportKeyType;
    @FXML
    private TextField exportKeyID, inboxMessagePrivateKey;
    @FXML
    private Label importKeyLabel, exportKeyLabel, encryptMessageMsg, inboxMessageInfos;
    @FXML
    private TextArea importFilePath, exportFilePath, inboxMessagePath, decryptedMessagePath;
    @FXML
    private AnchorPane anchorPaneImportKey, anchorPaneExportKey, anchorPaneReceiveMsg, anchorPaneSendMsg;
    @FXML
    private DialogPane inboxDialog;

    private boolean tabEntered = false;

    public void initialize() {
        // initialization here, if needed...
        System.out.println("init");

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
            case 0: viewKeys(); break;
        }
    }

    // Dummy function how to (refresh) populate tables (in first tab)
    public void viewKeys() {
        ObservableList<DummyObject> data = FXCollections.observableArrayList(
            new DummyObject(2512352, "br1"),
            new DummyObject(2512352, "br2"),
            new DummyObject(2512352, "br3"),
            new DummyObject(2512352, "br4"),
            new DummyObject(2512352, "br5"),
            new DummyObject(2512352, "br6")
        );

        this.privateKeysTableKeyIDCol.setCellValueFactory(
                new PropertyValueFactory<DummyObject, String>("id")
        );
        this.privateKeysTableOwnerIDCol.setCellValueFactory(
                new PropertyValueFactory<DummyObject, String>("owner")
        );
        this.privateKeysTableTimestampCol.setCellValueFactory(
                new PropertyValueFactory<DummyObject, String>("date")
        );

        this.privateKeysTable.setItems(data);
    }

    public void generateKey() {
        this.keyGenerationMsg.setText("Generise se...");

        String name = this.keyGenerationName.getText();
        String mail = this.keyGenerationMail.getText();
        String password = this.keyGenerationPassword.getText();
        String algorithm =  this.keyGenerationAlgorithms.getValue(); // NULL if not selected

        System.out.println("key Generation Button");
        System.out.println(name + ' ' + mail + ' ' + password + ' ' + algorithm);

    }

    public void deleteKey() {
        this.keyDeletionMsg.setText("Brise se...");

        String id = this.keyDeletionID.getText();
        String password = this.keyDeletionPassword.getText();

        System.out.println("key Generation Button");
        System.out.println(id + ' ' + password);
    }

    // FAJL PUTANJA
    public void selectImportFile() {
        System.out.println("select import file");

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Izaberite fajl za uvoz");
        Stage stage = (Stage)anchorPaneImportKey.getScene().getWindow();
        File file = fileChooser.showOpenDialog(stage);
        if (file != null) {
            System.out.println(file.getAbsolutePath());
            this.importFilePath.setText(file.getAbsolutePath());
        } else {
            System.out.println("Fajl je NULL");
        }
    }

    public void importKey() {
        System.out.println("import Key");
        this.importKeyLabel.setText("Uvozi se...");

        String filePath = this.importFilePath.getText();
        String keyType = ((RadioButton)importKeyType.getSelectedToggle()).getText();
        System.out.println(filePath + '\n' + keyType);
    }


    // DIREKTORIJUM PUTANJA
    public void selectExportFile() {
        System.out.println("select export file");

        DirectoryChooser directoryChooser = new DirectoryChooser();
        directoryChooser.setTitle("Izaberite direktorijum za izvoz");
        Stage stage = (Stage)anchorPaneExportKey.getScene().getWindow();
        File file = directoryChooser.showDialog(stage);
        if (file != null) {
            System.out.println(file.getAbsolutePath());
            this.exportFilePath.setText(file.getAbsolutePath());
            // this.exportFilePath.setWrapText(true);
        } else {
            System.out.println("Fajl je NULL");
        }
    }

    public void exportKey() {
        System.out.println("export Key");
        this.exportKeyLabel.setText("Izvozi se..");

        String keyId = this.exportKeyID.getText();
        String filePath = this.exportFilePath.getText();
        String keyType = ((RadioButton)exportKeyType.getSelectedToggle()).getText();
        System.out.println(filePath + '\n' + keyType + " " + keyId);

    }

    public void selectInboxMessage() {
        System.out.println("select inbox message");

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Izaberite kriptovanu prijemnu poruku");
        Stage stage = (Stage)anchorPaneReceiveMsg.getScene().getWindow();
        File file = fileChooser.showOpenDialog(stage);
        if (file != null) {
            System.out.println(file.getAbsolutePath());
            this.inboxMessagePath.setText(file.getAbsolutePath());
        } else {
            System.out.println("Fajl je NULL");
        }
    }

    public void selectDecryptedMessage() {
        System.out.println("select decrypt inbox message directory");

        DirectoryChooser directoryChooser = new DirectoryChooser();
        directoryChooser.setTitle("Izaberite direktorijum za enkriptovanu poruku");
        Stage stage = (Stage)anchorPaneReceiveMsg.getScene().getWindow();
        File file = directoryChooser.showDialog(stage);
        if (file != null) {
            System.out.println(file.getAbsolutePath());
            this.decryptedMessagePath.setText(file.getAbsolutePath());
            // this.decrpytedMessagePath.setWrapText(true);
        } else {
            System.out.println("Fajl je NULL");
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
        delay2.setOnFinished(event -> {this.inboxDialog.setVisible(false); this.inboxMessageInfos.setText("");});
        delay2.play();
    }

    public void closeInboxDialog() {
        this.inboxDialog.setVisible(false);
    }
}
