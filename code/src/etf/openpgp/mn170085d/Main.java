package etf.openpgp.mn170085d;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class Main extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception{
        Parent root = FXMLLoader.load(getClass().getResource("openpgp.fxml"));
        primaryStage.setTitle("Open PGP");
        primaryStage.setScene(new Scene(root, 800, 500));
        primaryStage.show();
//        primaryStage.setMaxHeight(650);
//        primaryStage.setMaxWidth(800);
        primaryStage.setWidth(800);
        primaryStage.setHeight(650);
        primaryStage.setResizable(false);
    }


    public static void main(String[] args) {
        launch(args);
    }
}
