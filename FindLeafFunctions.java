//Finds all self-contained (non-calling) functions
//@author jvstech
//@category Search
//@keybinding 
//@menupath 
//@toolbar 

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
import ghidra.program.model.block.graph.*;

public class FindLeafFunctions extends GhidraScript
{
  public void run() throws Exception
  {
    FunctionManager funcMgr = currentProgram.getFunctionManager();
    Listing listing = currentProgram.getListing();

    for (Function func : funcMgr.getFunctions(true))
    {
      if (!func.isThunk() && !hasCalls(listing, func))
      {
        println(func.getName());
      }
    }
  }

  private boolean hasCalls(Listing listing, Function func)
  {
    AddressSetView funcBody = func.getBody();
    for (Address addr : funcBody.getAddresses(true))
    {
      Instruction inst = listing.getInstructionAt(addr);
      if (inst != null)
      {
        FlowType flowType = inst.getFlowType();
        if (flowType.isCall())
        {
          return true;
        }
      }
    }

    return false;
  }
}
