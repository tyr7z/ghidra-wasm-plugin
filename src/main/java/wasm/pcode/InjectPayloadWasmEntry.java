package wasm.pcode;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadSleigh;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import wasm.analysis.WasmAnalysis;
import wasm.analysis.WasmFunctionAnalysis;
import wasm.format.WasmEnums.ValType;

/**
 * The "uponentry" injection for a Wasm function. We inject code to copy from
 * the artificial "inputs" registers into the real "locals" registers.
 */
public class InjectPayloadWasmEntry extends InjectPayloadSleigh {

	public InjectPayloadWasmEntry(String nm, int tp, String sourceName) {
		super(nm, tp, sourceName);
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		PcodeOpEmitter ops = new PcodeOpEmitter(program, con.baseAddr);

		WasmAnalysis state = WasmAnalysis.getState(program);
		WasmFunctionAnalysis funcAnalysis = state.getFunctionAnalysis(
				program.getFunctionManager().getFunctionContaining(con.baseAddr));
		if (funcAnalysis == null) {
			return ops.getPcodeOps();
		}

		Address inputBase = program.getRegister("i0").getAddress();
		Address localsBase = program.getRegister("l0").getAddress();
		ValType[] params = funcAnalysis.getSignature().getParams();
		ValType[] locals = funcAnalysis.getSignature().getLocals();
		for (int i = 0; i < params.length; i++) {
			ops.emitCopy(inputBase.add(i * 8L), localsBase.add(i * 8L), params[i].getSize());
		}
		Address zero = program.getAddressFactory().getConstantAddress(0L);
		for (int i = params.length; i < locals.length; i++) {
			ops.emitCopy(zero, localsBase.add(i * 8L), locals[i].getSize());
		}
		return ops.getPcodeOps();
	}
}
