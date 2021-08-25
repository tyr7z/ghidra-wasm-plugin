package wasm.format.sections;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;
import wasm.format.StructureUtils;
import wasm.format.sections.structures.WasmFuncType;

public class WasmTypeSection extends WasmSection {

	private Leb128 count;
	private List<WasmFuncType> types = new ArrayList<WasmFuncType>();

	public WasmTypeSection(BinaryReader reader) throws IOException {
		super(reader);
		count = new Leb128(reader);
		for (int i = 0; i < count.getValue(); ++i) {
			types.add(new WasmFuncType(reader));
		}
	}

	public WasmFuncType getType(int typeidx) {
		return types.get(typeidx);
	}

	public int getNumTypes() {
		return types.size();
	}

	@Override
	protected void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		StructureUtils.addField(structure, count, "count");
		for (int i = 0; i < types.size(); i++) {
			StructureUtils.addField(structure, types.get(i), "type_" + i);
		}
	}

	@Override
	public String getName() {
		return ".type";
	}
}
