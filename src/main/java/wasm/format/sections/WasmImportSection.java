package wasm.format.sections;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;
import wasm.format.StructureUtils;
import wasm.format.sections.structures.WasmImportEntry;

public class WasmImportSection extends WasmSection {

	private Leb128 count;
	private List<WasmImportEntry> imports = new ArrayList<WasmImportEntry>();

	public WasmImportSection(BinaryReader reader) throws IOException {
		super(reader);
		count = new Leb128(reader);
		for (int i = 0; i < count.getValue(); ++i) {
			imports.add(new WasmImportEntry(reader));
		}
	}

	public int getCount() {
		return (int) count.getValue();
	}

	public List<WasmImportEntry> getEntries() {
		return imports;
	}

	@Override
	protected void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		StructureUtils.addField(structure, count, "count");
		for (int i = 0; i < imports.size(); i++) {
			StructureUtils.addField(structure, imports.get(i), "import_" + i);
		}
	}

	@Override
	public String getName() {
		return ".import";
	}
}
