package wasm.pcode;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class PcodeOpEmitter {
	private Program program;
	private Address baseAddress;
	private List<PcodeOp> ops = new ArrayList<>();

	public PcodeOpEmitter(Program program, Address baseAddress) {
		this.program = program;
		this.baseAddress = baseAddress;
	}

	public PcodeOp[] getPcodeOps() {
		if (ops.size() == 0) {
			/* The decompiler may crash if we emit an empty array */
			emitNop();
		}
		return ops.toArray(new PcodeOp[0]);
	}

	private PcodeOp newOp(int opcode) {
		PcodeOp op = new PcodeOp(baseAddress, ops.size(), opcode);
		ops.add(op);
		return op;
	}

	private Varnode getRegister(String name) {
		Register register = program.getRegister(name);
		return new Varnode(register.getAddress(), register.getBitLength() / 8);
	}

	public void emitNop() {
		PcodeOp op = newOp(PcodeOp.COPY);
		Varnode lrVarnode = getRegister("LR");
		op.setInput(lrVarnode, 0);
		op.setOutput(lrVarnode);
	}

	public void emitCopy(Address fromAddr, Address toAddr, int size) {
		/* toAddr = fromAddr */
		PcodeOp op = newOp(PcodeOp.COPY);
		op.setInput(new Varnode(fromAddr, size), 0);
		op.setOutput(new Varnode(toAddr, size));
	}
}
