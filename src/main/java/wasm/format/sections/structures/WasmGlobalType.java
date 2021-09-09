package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;
import wasm.format.WasmEnums.ValType;

public class WasmGlobalType implements StructConverter {

	private ValType type;
	private int mutability;

	public WasmGlobalType(BinaryReader reader) throws IOException {
		type = ValType.fromByte(reader.readNextUnsignedByte());
		mutability = reader.readNextUnsignedByte();
	}

	public ValType getType() {
		return type;
	}

	public int getMutability() {
		return mutability;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder("global");
		builder.add(BYTE, "type");
		builder.add(BYTE, "mutability");
		return builder.toStructure();
	}
}
