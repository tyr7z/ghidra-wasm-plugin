package wasm.format.sections;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;

public class WasmGlobalSection extends WasmSection {
	
	public WasmGlobalSection (BinaryReader reader) throws IOException {
		super(reader);
		/* TODO */
	}

	@Override
	protected void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		
	}

	@Override
	public String getName() {
		return ".global";
	}
}
