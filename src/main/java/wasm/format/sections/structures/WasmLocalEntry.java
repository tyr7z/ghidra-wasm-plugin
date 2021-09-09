package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;

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
		StructureBuilder builder = new StructureBuilder("function_body");
		builder.add(count, "count");
		builder.add(BYTE, "type");
		return builder.toStructure();
	}
}
