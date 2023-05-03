/*
 * Copyright (c) 2023 Abc Xyz — All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//Find all local XRefs (references) in the decompiler window.
//@author saruman9
//@category References
//@keybinding ctrl x
//@menupath
//@toolbar

import docking.ComponentProvider;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.decompiler.DecompilerLocation;
import ghidra.app.decompiler.component.HighlightToken;
import ghidra.app.decompiler.component.TokenHighlights;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.script.GhidraScript;
import ghidra.app.tablechooser.AddressableRowObject;
import ghidra.app.tablechooser.ColumnDisplay;
import ghidra.app.tablechooser.StringColumnDisplay;
import ghidra.app.tablechooser.TableChooserDialog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;

import java.util.stream.Collectors;

public class FindLocalXRefs extends GhidraScript {

    @Override
    public void run() throws Exception {
        if (!(currentLocation instanceof DecompilerLocation)) {
            Msg.showError(this, null, "Error", "You should set the cursor in Decompiler window.");
            return;
        }
        ClangToken tokenAtCursor = ((DecompilerLocation) currentLocation).getToken();
        if (!(tokenAtCursor instanceof ClangVariableToken)) {
            Msg.showError(this, null, "Error", "You should set the cursor on the variable token.");
            return;
        }

        PluginTool tool = state.getTool();
        ComponentProvider activeComponentProvider = tool.getActiveComponentProvider();
        if (!(activeComponentProvider instanceof DecompilerProvider decompilerProvider)) {
            Msg.showError(this, null, "Error", "Decompiler's window should be active.");
            return;
        }

        TableChooserDialog tableDialog = createTableChooserDialog("XRefs for " + tokenAtCursor, null);
        configureTableColumns(tableDialog);

        TokenHighlights tokens =
                decompilerProvider.getController().getDecompilerPanel().getHighlightController().getPrimaryHighlights();
        for (HighlightToken token : tokens) {
            Address maxAddress = token.getToken().getMaxAddress();
            if (maxAddress != null) {
                XRefRow xRefRow = new XRefRow(maxAddress, token.getToken().getLineParent());
                tableDialog.add(xRefRow);
            }
        }

        tableDialog.show();
    }

    //
    // Table stuff
    //

    private void configureTableColumns(TableChooserDialog dialog) {

        StringColumnDisplay lineColumn = new StringColumnDisplay() {
            @Override
            public String getColumnName() {
                return "Line";
            }

            @Override
            public String getColumnValue(AddressableRowObject rowObject) {
                return ((XRefRow) rowObject).getLine().getAllTokens().stream().map(Object::toString)
                        .collect(Collectors.joining());
            }
        };

        ColumnDisplay<Integer> lineNumberColumn = new ghidra.app.tablechooser.AbstractComparableColumnDisplay<>() {

            @Override
            public Integer getColumnValue(AddressableRowObject rowObject) {
                return ((XRefRow) rowObject).getLine().getLineNumber();
            }

            @Override
            public String getColumnName() {
                return "Line Number";
            }
        };

        dialog.addCustomColumn(lineNumberColumn);
        dialog.addCustomColumn(lineColumn);
    }

    static class XRefRow implements AddressableRowObject {
        private final Address address;
        private final ClangLine line;

        public XRefRow(Address address, ClangLine line) {
            this.address = address;
            this.line = line;
        }

        public ClangLine getLine() {
            return line;
        }

        @Override
        public String toString() {
            return address.toString() + " : " + line;
        }

        @Override
        public Address getAddress() {
            return address;
        }
    }
}
