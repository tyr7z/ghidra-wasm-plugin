package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureUtils;
import wasm.format.WasmEnums.ValType;

public class WasmGlobalEntry implements StructConverter {

	private WasmGlobalType type;
	private ConstantExpression expr;

	public WasmGlobalEntry(BinaryReader reader) throws IOException {
		type = new WasmGlobalType(reader);
		expr = new ConstantExpression(reader);
	}

	public ValType getType() {
		return type.getType();
	}

	public boolean isMutable() {
		return (type.getMutability() & 1) != 0;
	}

	public DataType getDataType() {
		return type.getType().asDataType();
	}

	public byte[] getInitData() {
		return expr.getInitBytes();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = StructureUtils.createStructure("global_entry");
		StructureUtils.addField(structure, type, "type");
		StructureUtils.addField(structure, expr, "expr");
		return structure;
	}
}
