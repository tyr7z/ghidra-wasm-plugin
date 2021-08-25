package wasm.format.sections.structures;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;
import wasm.format.StructureUtils;

public class WasmName implements StructConverter {
	private Leb128 size;
	private String value;

	public WasmName(BinaryReader reader) throws IOException {
		size = new Leb128(reader);
		byte[] data = reader.readNextByteArray((int) size.getValue());
		value = new String(data, StandardCharsets.UTF_8);
	}

	public long getSize() {
		return size.getSize() + size.getValue();
	}

	public String getValue() {
		return value;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = StructureUtils.createStructure("name_" + size.getValue());
		StructureUtils.addField(structure, size, "size");
		StructureUtils.addStringField(structure, (int) size.getValue(), "value");
		return structure;
	}
}
