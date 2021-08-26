package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureUtils;

public class WasmNameLocalSubsection extends WasmNameSubsection {

	private WasmNameIndirectMap localNameMap;

	public WasmNameLocalSubsection(BinaryReader reader) throws IOException {
		super(reader);
		localNameMap = new WasmNameIndirectMap(reader);
	}

	public String getLocalName(int funcidx, int localidx) {
		return localNameMap.getEntry(funcidx, localidx);
	}

	@Override
	public void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		StructureUtils.addField(structure, localNameMap, "local_names");
	}

	@Override
	public String getName() {
		return ".name.local";
	}
}
