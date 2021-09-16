package wasm.pcode;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import wasm.analysis.WasmAnalysis;
import wasm.analysis.WasmFunctionAnalysis;
import wasm.analysis.WasmFunctionAnalysis.StackEffect;
import wasm.format.WasmEnums.ValType;

/**
 * Handle variable-length pushes from the stack to registers.
 * We use this to handle branches (pushing block arguments from temporary registers)
 * and function calls (pushing function return values from output registers).
 */
public class InjectPayloadWasmPush extends InjectPayloadCallother {

	public InjectPayloadWasmPush(String sourceName) {
		super(sourceName);
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		PcodeOpEmitter ops = new PcodeOpEmitter(program, con.baseAddr);

		long regoffset = con.inputlist.get(0).getOffset();
		Address baseAddress = program.getAddressFactory().getAddressSpace("register").getAddress(regoffset);

		WasmAnalysis state = WasmAnalysis.getState(program);
		WasmFunctionAnalysis funcAnalysis = state.getFunctionAnalysis(
				program.getFunctionManager().getFunctionContaining(con.baseAddr));
		if (funcAnalysis == null) {
			return ops.getPcodeOps();
		}

		StackEffect stackEffect = funcAnalysis.getStackEffect(con.baseAddr);
		if (stackEffect == null) {
			return ops.getPcodeOps();
		}

		long stackHeight = stackEffect.getPushHeight();
		ValType[] todo = stackEffect.getToPush();
		Address stackAddress = program.getRegister("s0").getAddress().add(stackHeight * 8);
		for (int i = 0; i < todo.length; i++) {
			ops.emitCopy(baseAddress.add(i * 8L), stackAddress.add(i * 8L), todo[i].getSize());
		}

		return ops.getPcodeOps();
	}
}
