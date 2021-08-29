package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureUtils;

public class WasmLocalEntry implements StructConverter {

	private LEB128 count;
	private int type;

	public WasmLocalEntry(BinaryReader reader) throws IOException {
		count = LEB128.readUnsignedValue(reader);
		type = reader.readNextUnsignedByte();
	}

	public int getCount() {
		return (int) count.asLong();
	}

	public int getType() {
		return type;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = StructureUtils.createStructure("function_body");
		StructureUtils.addField(structure, count, "count");
		StructureUtils.addField(structure, BYTE, "type");
		return structure;
	}
}
