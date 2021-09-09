package wasm.format.sections;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;
import wasm.format.sections.structures.WasmDataSegment;

public class WasmDataSection extends WasmSection {

	private LEB128 count;
	private List<WasmDataSegment> dataSegments = new ArrayList<WasmDataSegment>();

	public WasmDataSection(BinaryReader reader) throws IOException {
		super(reader);
		count = LEB128.readUnsignedValue(reader);
		for (int i = 0; i < count.asLong(); ++i) {
			dataSegments.add(new WasmDataSegment(reader));
		}
	}

	public List<WasmDataSegment> getSegments() {
		return Collections.unmodifiableList(dataSegments);
	}

	@Override
	protected void addToStructure(StructureBuilder builder) throws DuplicateNameException, IOException {
		builder.add(count, "count");
		for (int i = 0; i < dataSegments.size(); i++) {
			builder.add(dataSegments.get(i), "segment_" + i);
		}
	}

	@Override
	public String getName() {
		return ".data";
	}
}
