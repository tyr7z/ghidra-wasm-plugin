package wasm.format.sections;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;
import wasm.format.sections.structures.WasmResizableLimits;

public class WasmLinearMemorySection extends WasmSection {

	private Leb128 count;
	private List<WasmResizableLimits> limits = new ArrayList<WasmResizableLimits>();
	
	public WasmLinearMemorySection (BinaryReader reader) throws IOException {
		super(reader);
		count = new Leb128(reader);
		for (int i =0; i < count.getValue(); ++i) {
			limits.add(new WasmResizableLimits(reader));
		}	
	}


	@Override
	public void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		structure.add(count.toDataType(), count.toDataType().getLength(), "count", null);
		for (int i = 0; i < count.getValue(); ++i) {
			structure.add(limits.get(i).toDataType(), limits.get(i).toDataType().getLength(), "memory_type_"+i, null);
		}
	}

	@Override
	public String getName() {
		return ".linearMemory";
	}
}
