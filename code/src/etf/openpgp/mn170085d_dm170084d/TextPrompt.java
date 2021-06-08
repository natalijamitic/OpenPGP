package etf.openpgp.mn170085d_dm170084d;

import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.stage.Window;

/**
 * Klasa zaduzena za prikaz pop-up prozora koji ume da prikaze tekst.
 */
public class TextPrompt {

    /**
     * Incijalizacija prozora uz pomoc teksta koji se prikazuje.
     * @param owner
     * @param text
     */
    TextPrompt(Window owner, String text) {
        final Stage dialog = new Stage();

        dialog.setTitle("Info");
        dialog.initOwner(owner);
        dialog.initStyle(StageStyle.UTILITY);
        dialog.initModality(Modality.WINDOW_MODAL);
        dialog.setX(owner.getX() + owner.getWidth() / 2 - 100);
        dialog.setY(owner.getY() + owner.getHeight() / 2 - 100);

        final TextArea textField = new TextArea();
        final Button submitButton = new Button("OK");
        submitButton.setDefaultButton(true);
        submitButton.setOnAction(event -> dialog.close());
        textField.setPrefColumnCount(20);
        textField.setPrefRowCount(3);
        textField.setEditable(false);
        textField.setText(text);

        final VBox layout = new VBox(10);
        layout.setAlignment(Pos.CENTER);
        layout.setStyle("-fx-background-color: white; -fx-padding: 10;");
        layout.getChildren().setAll(
                textField,
                submitButton
        );

        dialog.setScene(new Scene(layout));
        dialog.showAndWait();
    }
}
