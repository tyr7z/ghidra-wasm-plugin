package wasm.format.sections;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;
import wasm.format.StructureUtils;

public class WasmFunctionSection extends WasmSection {

	private Leb128 count;
	private List<Leb128> types = new ArrayList<Leb128>();

	public WasmFunctionSection(BinaryReader reader) throws IOException {
		super(reader);
		count = new Leb128(reader);
		for (int i = 0; i < count.getValue(); ++i) {
			types.add(new Leb128(reader));
		}
	}

	public int getTypeIdx(int funcidx) {
		return (int) types.get(funcidx).getValue();
	}

	public int getTypeCount() {
		return types.size();
	}

	@Override
	protected void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		StructureUtils.addField(structure, count, "count");
		for (int i = 0; i < types.size(); i++) {
			StructureUtils.addField(structure, types.get(i), "function_" + i);
		}
	}

	@Override
	public String getName() {
		return ".function";
	}
}
