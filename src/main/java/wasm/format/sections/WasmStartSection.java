package wasm.format.sections;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;

public class WasmStartSection  extends WasmSection {

	public WasmStartSection (BinaryReader reader) throws IOException {
		super(reader);
	}

	@Override
	public void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		
	}

	@Override
	public String getName() {
		return ".start";
	}
}
