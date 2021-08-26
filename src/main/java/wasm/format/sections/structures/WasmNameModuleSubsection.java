package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureUtils;

public class WasmNameModuleSubsection extends WasmNameSubsection {

	private WasmName moduleName;

	public WasmNameModuleSubsection(BinaryReader reader) throws IOException {
		super(reader);
		moduleName = new WasmName(reader);
	}

	public String getModuleName() {
		return moduleName.getValue();
	}

	@Override
	public void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		StructureUtils.addField(structure, moduleName, "module_name");
	}

	@Override
	public String getName() {
		return ".name.module";
	}
}
