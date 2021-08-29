package wasm.format.sections;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureUtils;
import wasm.format.WasmEnums.WasmExternalKind;
import wasm.format.sections.structures.WasmExportEntry;

public class WasmExportSection extends WasmSection {

	private LEB128 count;
	private List<WasmExportEntry> exports = new ArrayList<WasmExportEntry>();

	public WasmExportSection(BinaryReader reader) throws IOException {
		super(reader);
		count = LEB128.readUnsignedValue(reader);
		for (int i = 0; i < count.asLong(); ++i) {
			exports.add(new WasmExportEntry(reader));
		}
	}

	public WasmExportEntry findMethod(int id) {
		for (WasmExportEntry entry : exports) {
			if (entry.getType() == WasmExternalKind.EXT_FUNCTION && entry.getIndex() == id) {
				return entry;
			}
		}
		return null;
	}

	@Override
	protected void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		StructureUtils.addField(structure, count, "count");
		for (int i = 0; i < exports.size(); i++) {
			StructureUtils.addField(structure, exports.get(i), "export_" + i);
		}
	}

	@Override
	public String getName() {
		return ".export";
	}
}
