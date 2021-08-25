package wasm.format.sections;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;
import wasm.format.StructureUtils;

public class WasmStartSection extends WasmSection {

	private Leb128 funcIdx;

	public WasmStartSection(BinaryReader reader) throws IOException {
		super(reader);
		funcIdx = new Leb128(reader);
	}

	public long getStartFunctionIndex() {
		return funcIdx.getValue();
	}

	@Override
	public void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		StructureUtils.addField(structure, funcIdx, "func");
	}

	@Override
	public String getName() {
		return ".start";
	}
}
