package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureUtils;

public class WasmGlobalType implements StructConverter {

	private int value_type;
	private int mutability;

	public WasmGlobalType(BinaryReader reader) throws IOException {
		value_type = reader.readNextUnsignedByte();
		mutability = reader.readNextUnsignedByte();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = StructureUtils.createStructure("global");
		StructureUtils.addField(structure, BYTE, "type");
		StructureUtils.addField(structure, BYTE, "mutability");
		return structure;
	}
}
