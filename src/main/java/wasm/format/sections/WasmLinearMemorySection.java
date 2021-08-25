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
import wasm.format.sections.structures.WasmResizableLimits;

public class WasmLinearMemorySection extends WasmSection {

	private Leb128 count;
	private List<WasmResizableLimits> limits = new ArrayList<WasmResizableLimits>();

	public WasmLinearMemorySection(BinaryReader reader) throws IOException {
		super(reader);
		count = new Leb128(reader);
		for (int i = 0; i < count.getValue(); ++i) {
			limits.add(new WasmResizableLimits(reader));
		}
	}

	public List<WasmResizableLimits> getMemories() {
		return Collections.unmodifiableList(limits);
	}

	@Override
	protected void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		StructureUtils.addField(structure, count, "count");
		for (int i = 0; i < limits.size(); i++) {
			StructureUtils.addField(structure, limits.get(i), "memory_type_" + i);
		}
	}

	@Override
	public String getName() {
		return ".linearMemory";
	}
}
