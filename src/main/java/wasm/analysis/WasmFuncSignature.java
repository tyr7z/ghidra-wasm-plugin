package wasm.analysis;

import ghidra.program.model.address.Address;
import wasm.format.WasmEnums.ValType;

public class WasmFuncSignature {
	private ValType[] params;
	private ValType[] returns;
	private String name;
	private Address startAddr;
	private Address endAddr;
	private ValType[] locals;

	public ValType[] getParams() {
		return params;
	}

	public ValType[] getReturns() {
		return returns;
	}

	public ValType[] getLocals() {
		return locals;
	}

	public String getName() {
		return name;
	}

	public Address getStartAddr() {
		return startAddr;
	}

	public Address getEndAddr() {
		return endAddr;
	}

	public boolean isImport() {
		return locals == null;
	}

	private static ValType[] translateTypeArray(byte[] types) {
		ValType[] res = new ValType[types.length];
		for (int i = 0; i < types.length; i++) {
			res[i] = ValType.fromByte(types[i]);
		}
		return res;
	}

	public WasmFuncSignature(byte[] paramTypes, byte[] returnTypes, String name, Address addr) {
		this.name = name;
		this.startAddr = addr;
		this.params = translateTypeArray(paramTypes);
		this.returns = translateTypeArray(returnTypes);
	}

	public WasmFuncSignature(byte[] paramTypes, byte[] returnTypes, String name, Address startAddr, Address endAddr, byte[] locals) {
		this(paramTypes, returnTypes, name, startAddr);
		this.endAddr = endAddr;
		this.locals = translateTypeArray(locals);
	}

	@Override
	public String toString() {
		return String.format("%s @ %s %dT -> %dT", name, startAddr.toString(), params.length, returns.length);
	}
}
