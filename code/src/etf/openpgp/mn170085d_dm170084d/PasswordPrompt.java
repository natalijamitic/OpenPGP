package etf.openpgp.mn170085d_dm170084d;

import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.stage.Window;

public class PasswordPrompt {
    private String result = "";

    PasswordPrompt(Window owner) {
        final Stage dialog = new Stage();

        dialog.setTitle("Unesite sifru za dekriptovanje");
        dialog.initOwner(owner);
        dialog.initStyle(StageStyle.UTILITY);
        dialog.initModality(Modality.WINDOW_MODAL);
        dialog.setX(owner.getX() + owner.getWidth() / 2 - 100);
        dialog.setY(owner.getY() + owner.getHeight() / 2 - 100);

        final PasswordField textField = new PasswordField();
        final Button submitButton = new Button("Dekriptuj");
        submitButton.setDefaultButton(true);
        submitButton.setOnAction(event -> dialog.close());
        textField.setMinHeight(TextField.USE_PREF_SIZE);

        final VBox layout = new VBox(10);
        layout.setAlignment(Pos.CENTER);
        layout.setStyle("-fx-background-color: white; -fx-padding: 10;");
        layout.getChildren().setAll(
                textField,
                submitButton
        );

        dialog.setScene(new Scene(layout));
        dialog.showAndWait();

        result = textField.getText();
    }

    public String getResult() {
        return result;
    }
}
