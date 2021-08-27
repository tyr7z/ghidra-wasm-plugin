package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureUtils;

public class WasmNameUnknownSubsection extends WasmNameSubsection {
	byte[] contents;

	public WasmNameUnknownSubsection(BinaryReader reader) throws IOException {
		super(reader);
		contents = reader.readNextByteArray((int) getContentSize());
	}

	@Override
	public void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		StructureUtils.addArrayField(structure, BYTE, (int) getContentSize(), "unknown" + id);
	}

	@Override
	public String getName() {
		return ".name.unknown" + id;
	}
}
