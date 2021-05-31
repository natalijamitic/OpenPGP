package etf.openpgp.mn170085d_dm170084d;

import etf.openpgp.mn170085d_dm170084d.keys.KeyGuiVisualisation;
import javafx.collections.ObservableList;
import javafx.event.EventHandler;
import javafx.scene.control.*;
import javafx.scene.input.*;

public class TableUtils {


    public static void installCopyPasteHandler(TableView<KeyGuiVisualisation> table) {
        table.setOnKeyPressed(new TableKeyEventHandler());
    }

    public static void installContextMenu(TableView<KeyGuiVisualisation> table){
       table.setOnMouseClicked(new TableMouseEventHandler());
    }

    public static class TableMouseEventHandler implements EventHandler<MouseEvent> {

        public void handle(final MouseEvent mouseEvent) {
            if(mouseEvent.getButton() == MouseButton.SECONDARY) {
                KeyGuiVisualisation key = (KeyGuiVisualisation) ((TableView<?>) mouseEvent.getSource()).getSelectionModel().getSelectedItem();

                ContextMenu cm = new ContextMenu();
                MenuItem mi0 = new MenuItem("Copy keyID");
                mi0.setOnAction(event -> copyToSystemClipboard(key.getId()));
                cm.getItems().add(mi0);

                cm.show((TableView<?>) mouseEvent.getSource(), mouseEvent.getScreenX(), mouseEvent.getScreenY());
            }
        }
    }

    public static class TableKeyEventHandler implements EventHandler<KeyEvent> {
        KeyCodeCombination copyKeyCodeCompination = new KeyCodeCombination(KeyCode.C, KeyCombination.CONTROL_ANY);

        public void handle(final KeyEvent keyEvent) {
            if (copyKeyCodeCompination.match(keyEvent)) {
                if( keyEvent.getSource() instanceof TableView) {
                    // copy to clipboard
                    copySelectionToClipboard( (TableView<?>) keyEvent.getSource());
                    System.out.println("Selection copied to clipboard");
                    keyEvent.consume();
                }
            }
        }
    }

    public static void copySelectionToClipboard(TableView<?> table) {
        StringBuilder clipboardString = new StringBuilder();
        ObservableList<TablePosition> positionList = table.getSelectionModel().getSelectedCells();
        int prevRow = -1;

        for (TablePosition position : positionList) {
            int row = position.getRow();
            int col = position.getColumn();
            Object cell = (Object) table.getColumns().get(col).getCellData(row);

            if (cell == null) {
                cell = "";
            }

            if (prevRow == row) {
                clipboardString.append('\t');
            } else if (prevRow != -1) {
                clipboardString.append('\n');
            }

            String text = cell.toString();
            clipboardString.append(text);

            prevRow = row;
        }

        copyToSystemClipboard(clipboardString.toString());

    }

    public static void copyToSystemClipboard(String text) {
        final ClipboardContent clipboardContent = new ClipboardContent();
        clipboardContent.putString(text);
        Clipboard.getSystemClipboard().setContent(clipboardContent);
    }
}