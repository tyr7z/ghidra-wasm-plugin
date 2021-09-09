package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;

public class WasmNameUnknownSubsection extends WasmNameSubsection {
	byte[] contents;

	public WasmNameUnknownSubsection(BinaryReader reader) throws IOException {
		super(reader);
		contents = reader.readNextByteArray((int) getContentSize());
	}

	@Override
	public void addToStructure(StructureBuilder builder) throws DuplicateNameException, IOException {
		builder.addArray(BYTE, (int) getContentSize(), "unknown" + id);
	}

	@Override
	public String getName() {
		return ".name.unknown" + id;
	}
}
