//Demonstrates printing caller decompiler calls to a function
//@author Mike J. Bell
//@category Decompiler
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

public class PrintCalls extends GhidraScript {

  public void run() throws Exception {
    FunctionManager functionManager = currentProgram.getFunctionManager();
    ReferenceManager referenceManager = currentProgram.getReferenceManager();
    Function function = functionManager.getFunctionContaining(currentAddress);
    if (function == null) {
      printerr("no current function");
      return;
    }
    DecompInterface decomp = new DecompInterface();
    try {
      decomp.openProgram(currentProgram);

      ReferenceIterator referenceIterator = referenceManager.getReferencesTo(function.getEntryPoint());
      while (referenceIterator.hasNext()) {
        Reference next = referenceIterator.next();
        // only iterate over references to our function that are calls
        if (next.getReferenceType().isCall()) {
          Function otherFunction = functionManager.getFunctionContaining(next.getFromAddress());
          if (otherFunction == null) {
            continue;
          }
          // yes, this is wasteful for multiple callers in the same other function
          DecompileResults results = decomp.decompileFunction(otherFunction, 120, monitor);
          ClangTokenGroup markup = results.getCCodeMarkup();
          ArrayList<ClangLine> lines = DecompilerUtils.toLines(markup);
          // find the C line that has the call in it
          for (ClangLine clangLine : lines) {
            boolean callFound = false;
            Address tokenAddress = null;

            int numTokens = clangLine.getNumTokens();
            for (int ii = 0; ii < numTokens; ++ii) {
              monitor.checkCanceled();
              ClangToken token = clangLine.getToken(ii);
              //print("st: " + token.getSyntaxType() + " pcop: " + token.getPcodeOp());
              PcodeOp pcodeOp = token.getPcodeOp();
              if (pcodeOp == null) {
                continue;
              }
              int opcode = pcodeOp.getOpcode();
              if (opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND || opcode == PcodeOp.CALLOTHER) {
                callFound = true;
                tokenAddress = token.getMinAddress();
              }
            }
            if (!callFound) {
              continue;
            }
            if (tokenAddress != null && tokenAddress.equals(next.getFromAddress())) {
              print("" + tokenAddress + "/" + clangLine + "\n");
            }
          }
        }
      }
    } finally {
      decomp.closeProgram();
    }
  }
}
