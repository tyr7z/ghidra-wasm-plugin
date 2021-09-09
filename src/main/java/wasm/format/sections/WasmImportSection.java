package wasm.format.sections;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;
import wasm.format.WasmEnums.WasmExternalKind;
import wasm.format.sections.structures.WasmImportEntry;

public class WasmImportSection extends WasmSection {

	private LEB128 count;
	private List<WasmImportEntry> importList = new ArrayList<>();
	private Map<WasmExternalKind, List<WasmImportEntry>> imports = new EnumMap<>(WasmExternalKind.class);

	public WasmImportSection(BinaryReader reader) throws IOException {
		super(reader);
		count = LEB128.readUnsignedValue(reader);
		for (int i = 0; i < count.asLong(); ++i) {
			WasmImportEntry entry = new WasmImportEntry(reader);
			WasmExternalKind kind = entry.getKind();
			if (!imports.containsKey(kind)) {
				imports.put(kind, new ArrayList<WasmImportEntry>());
			}
			imports.get(kind).add(entry);
			importList.add(entry);
		}
	}

	public List<WasmImportEntry> getImports(WasmExternalKind kind) {
		return imports.getOrDefault(kind, Collections.emptyList());
	}

	@Override
	protected void addToStructure(StructureBuilder builder) throws DuplicateNameException, IOException {
		builder.add(count, "count");
		for (int i = 0; i < importList.size(); i++) {
			builder.add(importList.get(i), "import_" + i);
		}
	}

	@Override
	public String getName() {
		return ".import";
	}
}
