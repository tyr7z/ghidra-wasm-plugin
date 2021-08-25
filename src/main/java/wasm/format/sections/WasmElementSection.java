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
import wasm.format.sections.structures.WasmElementSegment;

public class WasmElementSection extends WasmSection {

	private Leb128 count;
	private List<WasmElementSegment> elements = new ArrayList<WasmElementSegment>();

	public WasmElementSection(BinaryReader reader) throws IOException {
		super(reader);
		count = new Leb128(reader);
		for (int i = 0; i < count.getValue(); ++i) {
			elements.add(new WasmElementSegment(reader));
		}
	}

	public List<WasmElementSegment> getSegments() {
		return Collections.unmodifiableList(elements);
	}

	@Override
	protected void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		StructureUtils.addField(structure, count, "count");
		for (int i = 0; i < elements.size(); i++) {
			StructureUtils.addField(structure, elements.get(i), "element_" + i);
		}
	}

	@Override
	public String getName() {
		return ".element";
	}
}
