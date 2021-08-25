package wasm.format.sections;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureUtils;

public class WasmUnknownCustomSection extends WasmCustomSection {
	byte[] contents;

	public WasmUnknownCustomSection(BinaryReader reader) throws IOException {
		super(reader);
		contents = reader.readNextByteArray((int) getCustomSize());
	}

	@Override
	protected void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		super.addToStructure(structure);
		StructureUtils.addArrayField(structure, BYTE, (int) getCustomSize(), "custom");
	}

	@Override
	public String getName() {
		return ".custom";
	}
}
