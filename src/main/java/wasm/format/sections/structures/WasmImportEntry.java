package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;
import wasm.format.WasmEnums.WasmExternalKind;

public class WasmImportEntry implements StructConverter {

	private WasmName module;
	private WasmName field;
	private WasmExternalKind kind;

	private LEB128 function_type;
	private WasmTableType table_type;
	private WasmResizableLimits memory_type;
	private WasmGlobalType global_type;

	private long startOffset, endOffset;

	public WasmImportEntry(BinaryReader reader) throws IOException {
		startOffset = reader.getPointerIndex();
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
		endOffset = reader.getPointerIndex();
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

	public long getEntryOffset() {
		return startOffset;
	}

	public long getEntrySize() {
		return endOffset - startOffset;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder("import_" + getName());
		builder.add(module, "module");
		builder.add(field, "field");
		builder.add(BYTE, "kind");
		switch (kind) {
		case EXT_FUNCTION:
			builder.add(function_type, "type");
			break;
		case EXT_TABLE:
			builder.add(table_type, "type");
			break;
		case EXT_MEMORY:
			builder.add(memory_type, "type");
			break;
		case EXT_GLOBAL:
			builder.add(global_type, "type");
			break;
		default:
			break;
		}
		return builder.toStructure();
	}
}
