package wasm.format.sections;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;

public class WasmUnknownCustomSection extends WasmCustomSection {
	byte[] contents;

	public WasmUnknownCustomSection(BinaryReader reader) throws IOException {
		super(reader);
		contents = reader.readNextByteArray((int) getCustomSize());
	}

	@Override
	protected void addToStructure(StructureBuilder builder) throws DuplicateNameException, IOException {
		super.addToStructure(builder);
		builder.addArray(BYTE, (int) getCustomSize(), "custom");
	}

	@Override
	public String getName() {
		return ".custom";
	}
}
