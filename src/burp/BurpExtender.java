package burp;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IHttpListener, IMessageEditorController {
    private final List<ReflectedEntry> reflectedEntryList = new ArrayList<>();
    private ReflectionAnalyzer analyzer;
    private PrintWriter stdout;
    private IBurpExtenderCallbacks callbacks;
    private JSplitPane splitPane;
    private JSplitPane splitPane2;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private ParametersTable parametersTable;
    private IHttpRequestResponse currentlyDisplayedItem;

    // Right click menu elements
    private JMenuItem menuItemScannerAll;
    private JMenuItem menuItemScannerParameters;
    private JMenuItem menuItemIntruder;
    private JMenuItem menuItemRepeater;
    private JMenuItem menuItemCopyURL;
    private JMenuItem menuItemDeleteItem;
    private JMenuItem menuItemClearList;


    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        this.analyzer = new ReflectionAnalyzer(callbacks);

        // set our extension name
        callbacks.setExtensionName("Stateful Reflection v0.01");

        // obtain our output and error streams
        stdout = new PrintWriter(callbacks.getStdout(), true);

        // create our UI
        SwingUtilities.invokeLater(() -> {
            // Main split pane
            splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
            splitPane.setResizeWeight(0.4f);
            splitPane2 = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
            splitPane2.setResizeWeight(0.35f);

            // Table of reflected entries
            ReflectedTable requestTable = new ReflectedTable(BurpExtender.this);
            ParametersTableModel parametersTableModel = new ParametersTableModel();

            parametersTable = new ParametersTable(parametersTableModel);
            parametersTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);


            // Setting the columns width
            requestTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
            requestTable.getColumnModel().getColumn(0).setPreferredWidth(30);
            requestTable.getColumnModel().getColumn(1).setPreferredWidth(300);
            requestTable.getColumnModel().getColumn(2).setPreferredWidth(80);
            requestTable.getColumnModel().getColumn(3).setPreferredWidth(500);
            requestTable.getColumnModel().getColumn(4).setPreferredWidth(80);
            requestTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);


            // Creating popup menu
            JPopupMenu popupMenu = new JPopupMenu();
            menuItemScannerAll = new JMenuItem("Active scan whole request");
            menuItemScannerParameters = new JMenuItem("Active scan reflected parameters");
            menuItemIntruder = new JMenuItem("Send request to Intruder");
            menuItemRepeater = new JMenuItem("Send request to Repeater");
            menuItemCopyURL = new JMenuItem("Copy URL");
            menuItemDeleteItem = new JMenuItem("Delete item");
            menuItemClearList = new JMenuItem("Clear list");


            menuItemScannerAll.addActionListener(requestTable);
            menuItemScannerParameters.addActionListener(requestTable);
            menuItemIntruder.addActionListener(requestTable);
            menuItemRepeater.addActionListener(requestTable);
            menuItemCopyURL.addActionListener(requestTable);
            menuItemDeleteItem.addActionListener(requestTable);
            menuItemClearList.addActionListener(requestTable);

            popupMenu.add(menuItemScannerAll);
            popupMenu.add(menuItemScannerParameters);
            popupMenu.add(menuItemIntruder);
            popupMenu.add(menuItemRepeater);
            popupMenu.add(new JSeparator());
            popupMenu.add(menuItemCopyURL);
            popupMenu.add(menuItemDeleteItem);
            popupMenu.add(new JSeparator());
            popupMenu.add(menuItemClearList);

            requestTable.setComponentPopupMenu(popupMenu);

            JScrollPane scrollPane = new JScrollPane(requestTable);
            JScrollPane scrollPane2 = new JScrollPane(parametersTable);

            splitPane.setLeftComponent(scrollPane);
            splitPane2.setLeftComponent(scrollPane2);

            // Tabs with request/response viewers
            JTabbedPane tabs = new JTabbedPane();
            requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
            responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
            tabs.addTab("Request", requestViewer.getComponent());
            tabs.addTab("Response", responseViewer.getComponent());

            splitPane.setRightComponent(splitPane2);
            splitPane2.setRightComponent(tabs);
            splitPane.setDividerLocation(0.5);
            splitPane2.setDividerLocation(0.3);

            // Customize our UI components
            callbacks.customizeUiComponent(splitPane);
            callbacks.customizeUiComponent(splitPane2);
            callbacks.customizeUiComponent(requestTable);
            callbacks.customizeUiComponent(parametersTable);
            callbacks.customizeUiComponent(scrollPane);
            callbacks.customizeUiComponent(scrollPane2);
            callbacks.customizeUiComponent(tabs);


            // add the custom tab to Burp's UI
            callbacks.addSuiteTab(BurpExtender.this);

            // register ourselves as an HTTP listener
            callbacks.registerHttpListener(BurpExtender.this);

            stdout.println("Stateful Reflection plugin v0.01");
            stdout.println("Source: https://github.com/isaquevieira/stateful-reflected-parameters");
        });

    }

    @Override
    public String getTabCaption() {
        return "Stateful Reflection";
    }

    @Override
    public Component getUiComponent() {
        return splitPane;
    }

    //
    // implement IHttpListener
    //
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        analyzer.analyzeHttpResponse(toolFlag, messageIsRequest, messageInfo);
        ReflectedEntry entry = analyzer.analyzeHttpRequest(toolFlag, messageIsRequest, messageInfo);
        if (entry != null) {
            synchronized (reflectedEntryList) {
                int row = reflectedEntryList.size();
                reflectedEntryList.add(entry);
                fireTableRowsInserted(row, row);
            }
        }
    }

    //
    // extend AbstractTableModel
    //

    @Override
    public int getRowCount() {
        return reflectedEntryList.size();
    }

    @Override
    public int getColumnCount() {
        return 5;
    }

    @Override
    public String getColumnName(int columnIndex) {
        return switch (columnIndex) {
            case 0 -> "#";
            case 1 -> "Host";
            case 2 -> "Method";
            case 3 -> "URL";
            case 4 -> "Tool";
            default -> "";
        };
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        ReflectedEntry reflectedEntry = reflectedEntryList.get(rowIndex);

        return switch (columnIndex) {
            case 0 -> Integer.toString(rowIndex + 1);
            case 1 -> (reflectedEntry.url.getProtocol() + "://" + reflectedEntry.url.getHost());
            case 2 -> reflectedEntry.method;
            case 3 -> reflectedEntry.url.getFile();
            case 4 -> reflectedEntry.tool;
            default -> "";
        };
    }

    //
    // implement IMessageEditorController
    // this allows our request/response viewers to obtain details about the messages being displayed
    //

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }


    //
    // Extend JTable to handle cell selection
    //

    // Parameters table
    private static class ParametersTableModel extends AbstractTableModel {
        ReflectedEntry reflectedEntry;

        public ParametersTableModel() {
            this.reflectedEntry = new ReflectedEntry();
        }

        public void reloadValues(ReflectedEntry reflectedEntry) {
            this.reflectedEntry = reflectedEntry;
            this.fireTableDataChanged();
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            return reflectedEntry.parameters.get(rowIndex)[columnIndex];
        }

        @Override
        public int getColumnCount() {
            return 3;
        }

        @Override
        public int getRowCount() {
            return reflectedEntry.parameters.size();
        }

        @Override
        public String getColumnName(int columnIndex) {
            return switch (columnIndex) {
                case 0 -> "Parameter name";
                case 1 -> "Parameter value";
                case 2 -> "Reflected value";
                default -> "";
            };
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return String.class;
        }
    }

    //
    // Class to hold details of each reflected entry
    //


    private class ReflectedTable extends JTable implements ActionListener {
        public ReflectedTable(TableModel tableModel) {
            super(tableModel);
        }

        @Override
        public void actionPerformed(ActionEvent event) {
            JMenuItem menu = (JMenuItem) event.getSource();
            int row = this.getSelectedRow();

            // If no row is selected
            if (row == -1)
                return;
            ReflectedEntry reflectedEntry = reflectedEntryList.get(row);
            boolean useHttps = reflectedEntry.url.getProtocol().equalsIgnoreCase("https");
            if (menu == menuItemScannerAll) {
                // Send the request to the Scanner
                callbacks.doActiveScan(reflectedEntry.url.getHost(), reflectedEntry.url.getPort(), useHttps, reflectedEntry.requestResponse.getRequest());
            } else if (menu == menuItemScannerParameters) {
                // Send the reflected parameters to the Scanner
                callbacks.doActiveScan(reflectedEntry.url.getHost(), reflectedEntry.url.getPort(), useHttps, reflectedEntry.requestResponse.getRequest(), reflectedEntry.requestResponse.getRequestMarkers());

            } else if (menu == menuItemIntruder) {
                // Send the request to the Intruder
                callbacks.sendToIntruder(reflectedEntry.url.getHost(), reflectedEntry.url.getPort(), useHttps,
                        reflectedEntry.requestResponse.getRequest(), reflectedEntry.requestResponse.getRequestMarkers());
            } else if (menu == menuItemRepeater) {
                // Send the request to the Repeater
                callbacks.sendToRepeater(reflectedEntry.url.getHost(), reflectedEntry.url.getPort(), useHttps, reflectedEntry.requestResponse.getRequest(), null);
            } else if (menu == menuItemCopyURL) {
                // Copy URL to the clipboard
                StringSelection stringSelection = new StringSelection(reflectedEntry.url.toString());
                Clipboard clpbrd = Toolkit.getDefaultToolkit().getSystemClipboard();
                clpbrd.setContents(stringSelection, null);
            } else if (menu == menuItemDeleteItem) {
                reflectedEntryList.remove(row);

                //Reload the request table
                ((AbstractTableModel) this.getModel()).fireTableDataChanged();

                // Clear the parameters table
                ((ParametersTableModel) parametersTable.getModel()).reloadValues(new ReflectedEntry());

                // Clear request/response
                requestViewer.setMessage(new byte[0], true);
                responseViewer.setMessage(new byte[0], false);

            } else if (menu == menuItemClearList) {
                reflectedEntryList.clear();

                //Reload the request table
                ((AbstractTableModel) this.getModel()).fireTableDataChanged();

                // Clear the parameters table
                ((ParametersTableModel) parametersTable.getModel()).reloadValues(new ReflectedEntry());

                // Clear request/response
                requestViewer.setMessage(new byte[0], true);
                responseViewer.setMessage(new byte[0], false);

            }
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            // Reloading the Request/Response tabs
            ReflectedEntry reflectedEntry = reflectedEntryList.get(row);
            requestViewer.setMessage(reflectedEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(reflectedEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = reflectedEntry.requestResponse;

            // Reloading the Parameters list
            parametersTable.reloadValues(reflectedEntry);
            super.changeSelection(row, col, toggle, extend);
        }
    }

    private class ParametersTable extends JTable implements ActionListener {
        private final JPopupMenu popupMenu;
        private final JMenuItem menuItemScannerParameter;

        public ParametersTable(TableModel tableModel) {
            super(tableModel);

            // Creating popup menu
            popupMenu = new JPopupMenu();
            menuItemScannerParameter = new JMenuItem("Scan parameter");
            menuItemScannerParameter.addActionListener(this);
            popupMenu.add(menuItemScannerParameter);
            this.setComponentPopupMenu(popupMenu);
        }

        private void reloadValues(ReflectedEntry reflectedEntry) {
            ((ParametersTableModel) this.getModel()).reloadValues(reflectedEntry);
        }

        @Override
        public void actionPerformed(ActionEvent event) {
            int row = this.getSelectedRow();
            if (row == -1)
                return;
            ReflectedEntry reflectedEntry = ((ParametersTableModel) this.getModel()).reflectedEntry;
            List<int[]> param = new ArrayList<>();
            param.add(reflectedEntry.requestResponse.getRequestMarkers().get(row));
            callbacks.doActiveScan(reflectedEntry.url.getHost(), reflectedEntry.url.getPort(),
                    reflectedEntry.url.getProtocol().equalsIgnoreCase("https"), reflectedEntry.requestResponse.getRequest(), param);
        }
    }
}
