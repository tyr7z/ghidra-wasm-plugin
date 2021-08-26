package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureUtils;

public class WasmNameFunctionSubsection extends WasmNameSubsection {

	private WasmNameMap functionNameMap;

	public WasmNameFunctionSubsection(BinaryReader reader) throws IOException {
		super(reader);
		functionNameMap = new WasmNameMap(reader);
	}

	public String getFunctionName(long idx) {
		return functionNameMap.getEntry(idx);
	}

	@Override
	public void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		StructureUtils.addField(structure, functionNameMap, "function_names");
	}

	@Override
	public String getName() {
		return ".name.function";
	}
}
