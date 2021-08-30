package wasm.pcode;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class PcodeOpEmitter {
	private Program program;
	private Address baseAddress;
	private AddressSpace constSpace;
	private Varnode spVarnode;
	private Varnode defSpaceId;
	private List<PcodeOp> ops = new ArrayList<>();

	public PcodeOpEmitter(Program program, Address baseAddress) {
		this.program = program;
		this.baseAddress = baseAddress;
		constSpace = program.getAddressFactory().getConstantSpace();
		spVarnode = getRegister("SP");
		defSpaceId = getConstant(program.getAddressFactory().getDefaultAddressSpace().getSpaceID(), 4);
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

	private Varnode getConstant(long val, int size) {
		return new Varnode(constSpace.getAddress(val), size);
	}

	private Varnode getRegister(String name) {
		Register register = program.getRegister(name);
		return new Varnode(register.getAddress(), register.getBitLength() / 8);
	}

	public void emitNop() {
		PcodeOp op = newOp(PcodeOp.COPY);
		op.setInput(spVarnode, 0);
		op.setOutput(spVarnode);
	}

	public void emitCopy(Address fromAddr, Address toAddr, int size) {
		/* toAddr = fromAddr */
		PcodeOp op = newOp(PcodeOp.COPY);
		op.setInput(new Varnode(fromAddr, size), 0);
		op.setOutput(new Varnode(toAddr, size));
	}

	public void emitPop(Address toAddr, int size) {
		/* toAddr = *SP */
		PcodeOp loadOp = newOp(PcodeOp.LOAD);
		loadOp.setInput(defSpaceId, 0);
		loadOp.setInput(spVarnode, 1);
		loadOp.setOutput(new Varnode(toAddr, size));

		/* SP = SP + 8 */
		PcodeOp addOp = newOp(PcodeOp.INT_ADD);
		addOp.setInput(spVarnode, 0);
		addOp.setInput(getConstant(8, spVarnode.getSize()), 1);
		addOp.setOutput(spVarnode);
	}

	public void emitPush(Address fromAddr, int size) {
		/* SP = SP - 8 */
		PcodeOp addOp = newOp(PcodeOp.INT_SUB);
		addOp.setInput(spVarnode, 0);
		addOp.setInput(getConstant(8, spVarnode.getSize()), 1);
		addOp.setOutput(spVarnode);

		/* *SP = fromAddr */
		PcodeOp storeOp = newOp(PcodeOp.STORE);
		storeOp.setInput(defSpaceId, 0);
		storeOp.setInput(spVarnode, 1);
		storeOp.setInput(new Varnode(fromAddr, size), 2);
	}
}