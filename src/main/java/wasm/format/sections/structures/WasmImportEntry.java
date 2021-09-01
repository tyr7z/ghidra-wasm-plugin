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

public class WasmImportEntry implements StructConverter {

	private WasmName module;
	private WasmName field;
	private WasmExternalKind kind;

	private LEB128 function_type;
	private WasmTableType table_type;
	private WasmResizableLimits memory_type;
	private WasmGlobalType global_type;

	public WasmImportEntry(BinaryReader reader) throws IOException {
		module = new WasmName(reader);
		field = new WasmName(reader);
		kind = WasmExternalKind.values()[reader.readNextByte()];
		switch (kind) {
		case EXT_FUNCTION:
			function_type = LEB128.readUnsignedValue(reader);
			break;
		case EXT_TABLE:
			table_type = new WasmTableType(reader);
			break;
		case EXT_MEMORY:
			memory_type = new WasmResizableLimits(reader);
			break;
		case EXT_GLOBAL:
			global_type = new WasmGlobalType(reader);
			break;
		default:
			break;
		}
	}

	public WasmExternalKind getKind() {
		return kind;
	}

	public int getFunctionType() {
		if (kind != WasmExternalKind.EXT_FUNCTION) {
			throw new IllegalArgumentException("Cannot get function type of non-function import");
		}
		return (int) function_type.asLong();
	}

	public WasmTableType getTableType() {
		if (kind != WasmExternalKind.EXT_TABLE) {
			throw new IllegalArgumentException("Cannot get table type of non-table import");
		}
		return table_type;
	}

	public WasmResizableLimits getMemoryType() {
		if (kind != WasmExternalKind.EXT_MEMORY) {
			throw new IllegalArgumentException("Cannot get memory type of non-memory import");
		}
		return memory_type;
	}

	public WasmGlobalType getGlobalType() {
		if (kind != WasmExternalKind.EXT_GLOBAL) {
			throw new IllegalArgumentException("Cannot get global type of non-global import");
		}
		return global_type;
	}

	public String getModule() {
		return module.getValue();
	}

	public String getName() {
		return field.getValue();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = StructureUtils.createStructure("import_" + getName());
		StructureUtils.addField(structure, module, "module");
		StructureUtils.addField(structure, field, "field");
		StructureUtils.addField(structure, BYTE, "kind");
		switch (kind) {
		case EXT_FUNCTION:
			StructureUtils.addField(structure, function_type, "type");
			break;
		case EXT_TABLE:
			StructureUtils.addField(structure, table_type, "type");
			break;
		case EXT_MEMORY:
			StructureUtils.addField(structure, memory_type, "type");
			break;
		case EXT_GLOBAL:
			StructureUtils.addField(structure, global_type, "type");
			break;
		default:
			break;
		}
		return structure;
	}
}
