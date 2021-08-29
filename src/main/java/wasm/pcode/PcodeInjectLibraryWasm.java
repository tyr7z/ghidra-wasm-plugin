package wasm.pcode;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.PcodeInjectLibrary;

public class PcodeInjectLibraryWasm extends PcodeInjectLibrary {

	public final static long REG_OFF_LOCALS = 0x1000000000L;
	public final static long REG_OFF_INPUTS = 0x2000000000L;
	public final static long REG_OFF_OUTPUTS = 0x3000000000L;

	public PcodeInjectLibraryWasm(SleighLanguage l) {
		super(l);
	}

	public PcodeInjectLibraryWasm(PcodeInjectLibraryWasm op2) {
		super(op2);
	}

	@Override
	public PcodeInjectLibrary clone() {
		return new PcodeInjectLibraryWasm(this);
	}

	@Override
	public InjectPayload allocateInject(String sourceName, String name, int tp) {
		if (tp == InjectPayload.CALLMECHANISM_TYPE) {
			return new InjectPayloadWasmEntry(name, tp, sourceName);
		} else if (tp == InjectPayload.CALLOTHERFIXUP_TYPE) {
			switch (name) {
			case "popCallOther":
				return new InjectPayloadWasmPop(sourceName);
			case "pushCallOther":
				return new InjectPayloadWasmPush(sourceName);
			}
		}
		return super.allocateInject(sourceName, name, tp);
	}
}