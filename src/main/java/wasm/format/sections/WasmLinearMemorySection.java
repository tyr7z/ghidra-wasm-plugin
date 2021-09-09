package wasm.format.sections;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;
import wasm.format.sections.structures.WasmResizableLimits;

public class WasmLinearMemorySection extends WasmSection {

	private LEB128 count;
	private List<WasmResizableLimits> limits = new ArrayList<WasmResizableLimits>();

	public WasmLinearMemorySection(BinaryReader reader) throws IOException {
		super(reader);
		count = LEB128.readUnsignedValue(reader);
		for (int i = 0; i < count.asLong(); ++i) {
			limits.add(new WasmResizableLimits(reader));
		}
	}

	public List<WasmResizableLimits> getMemories() {
		return Collections.unmodifiableList(limits);
	}

	@Override
	protected void addToStructure(StructureBuilder builder) throws DuplicateNameException, IOException {
		builder.add(count, "count");
		for (int i = 0; i < limits.size(); i++) {
			builder.add(limits.get(i), "memory_type_" + i);
		}
	}

	@Override
	public String getName() {
		return ".linearMemory";
	}
}
