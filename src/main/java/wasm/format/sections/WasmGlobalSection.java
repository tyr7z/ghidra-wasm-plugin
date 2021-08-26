package wasm.format.sections;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;
import wasm.format.StructureUtils;
import wasm.format.sections.structures.WasmGlobalEntry;

public class WasmGlobalSection extends WasmSection {

	private Leb128 count;
	private List<WasmGlobalEntry> globals = new ArrayList<>();

	public WasmGlobalSection(BinaryReader reader) throws IOException {
		super(reader);
		count = new Leb128(reader);
		for (int i = 0; i < count.getValue(); ++i) {
			globals.add(new WasmGlobalEntry(reader));
		}
	}

	public List<WasmGlobalEntry> getEntries() {
		return Collections.unmodifiableList(globals);
	}

	@Override
	protected void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		StructureUtils.addField(structure, count, "count");
		for (int i = 0; i < globals.size(); i++) {
			StructureUtils.addField(structure, globals.get(i), "global_" + i);
		}
	}

	@Override
	public String getName() {
		return ".global";
	}
}
