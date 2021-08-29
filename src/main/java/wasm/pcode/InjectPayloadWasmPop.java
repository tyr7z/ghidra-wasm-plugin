package wasm.pcode;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import wasm.analysis.WasmAnalysis;
import wasm.analysis.WasmFunctionPreAnalysis;
import wasm.analysis.WasmFunctionPreAnalysis.StackEffect;
import wasm.format.WasmEnums.ValType;

/**
 * The "uponentry" injection for a Wasm function. We inject code to copy from
 * the artificial "inputs" registers into the real "locals" registers.
 */
public class InjectPayloadWasmPop extends InjectPayloadCallother {

	public InjectPayloadWasmPop(String sourceName) {
		super(sourceName);
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		PcodeOpEmitter ops = new PcodeOpEmitter(program, con.baseAddr);

		long regoffset = con.inputlist.get(0).getOffset();
		Address baseAddress = program.getAddressFactory().getAddressSpace("register").getAddress(regoffset);

		WasmAnalysis state = WasmAnalysis.getState(program);
		WasmFunctionPreAnalysis funcAnalysis = state.getFunctionPreAnalysis(
				program.getFunctionManager().getFunctionContaining(con.baseAddr));
		if (funcAnalysis == null) {
			return ops.getPcodeOps();
		}

		StackEffect stackEffect = funcAnalysis.getStackEffect(con.baseAddr);
		if (stackEffect == null) {
			return ops.getPcodeOps();
		}

		ValType[] todo = stackEffect.getToPop();
		for (int i = todo.length - 1; i >= 0; i--) {
			ops.emitPop(baseAddress.add(8 * i), todo[i].getSize());
		}

		return ops.getPcodeOps();
	}
}