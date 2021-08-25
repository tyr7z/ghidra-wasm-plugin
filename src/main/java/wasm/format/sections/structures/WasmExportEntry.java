package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;
import wasm.format.StructureUtils;

public class WasmExportEntry implements StructConverter {

	private WasmName name;
	private WasmExternalKind kind;
	private Leb128 index;

	public enum WasmExternalKind {
		KIND_FUNCTION,
		KIND_TABLE,
		KIND_MEMORY,
		KIND_GLOBAL
	}

	public WasmExportEntry(BinaryReader reader) throws IOException {
		name = new WasmName(reader);
		kind = WasmExternalKind.values()[reader.readNextByte()];
		index = new Leb128(reader);
	}

	public String getName() {
		return name.getValue();
	}

	public int getIndex() {
		return (int) index.getValue();
	}

	public WasmExternalKind getType() {
		return kind;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = StructureUtils.createStructure("export_" + index.getValue());
		StructureUtils.addField(structure, name, "name");
		StructureUtils.addField(structure, BYTE, "kind");
		StructureUtils.addField(structure, index, "index");
		return structure;
	}
}
