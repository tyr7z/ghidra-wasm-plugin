package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;
import wasm.format.WasmEnums.WasmExternalKind;

public class WasmExportEntry implements StructConverter {

	private WasmName name;
	private WasmExternalKind kind;
	private LEB128 index;

	public WasmExportEntry(BinaryReader reader) throws IOException {
		name = new WasmName(reader);
		kind = WasmExternalKind.values()[reader.readNextByte()];
		index = LEB128.readUnsignedValue(reader);
	}

	public String getName() {
		return name.getValue();
	}

	public int getIndex() {
		return (int) index.asLong();
	}

	public WasmExternalKind getKind() {
		return kind;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder("export_" + getIndex());
		builder.add(name, "name");
		builder.add(BYTE, "kind");
		builder.add(index, "index");
		return builder.toStructure();
	}
}
