package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureUtils;
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

	public WasmExternalKind getType() {
		return kind;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = StructureUtils.createStructure("export_" + getIndex());
		StructureUtils.addField(structure, name, "name");
		StructureUtils.addField(structure, BYTE, "kind");
		StructureUtils.addField(structure, index, "index");
		return structure;
	}
}
