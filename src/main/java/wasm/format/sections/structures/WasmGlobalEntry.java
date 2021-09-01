package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureUtils;
import wasm.format.WasmModule;

public class WasmGlobalEntry implements StructConverter {

	private WasmGlobalType type;
	private ConstantExpression expr;

	public WasmGlobalEntry(BinaryReader reader) throws IOException {
		type = new WasmGlobalType(reader);
		expr = new ConstantExpression(reader);
	}

	public WasmGlobalType getGlobalType() {
		return type;
	}

	public byte[] asBytes(WasmModule module) {
		return expr.asBytes(module);
	}

	public Long asReference(WasmModule module) {
		return expr.asReference(module);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = StructureUtils.createStructure("global_entry");
		StructureUtils.addField(structure, type, "type");
		StructureUtils.addField(structure, expr, "expr");
		return structure;
	}
}
