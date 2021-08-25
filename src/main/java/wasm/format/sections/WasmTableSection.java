package wasm.format.sections;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;
import wasm.format.StructureUtils;
import wasm.format.sections.structures.WasmTableType;

public class WasmTableSection extends WasmSection {

	private Leb128 count;
	private List<WasmTableType> tables = new ArrayList<WasmTableType>();

	public WasmTableSection(BinaryReader reader) throws IOException {
		super(reader);
		count = new Leb128(reader);
		for (int i = 0; i < count.getValue(); ++i) {
			tables.add(new WasmTableType(reader));
		}
	}

	@Override
	protected void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		StructureUtils.addField(structure, count, "count");
		for (int i = 0; i < tables.size(); i++) {
			StructureUtils.addField(structure, tables.get(i), "table_" + i);
		}
	}

	@Override
	public String getName() {
		return ".table";
	}
}
