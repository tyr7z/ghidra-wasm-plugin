package wasm.format.sections;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;
import wasm.format.sections.structures.WasmName;

public class WasmNameSection extends WasmCustomSection {
	WasmName moduleName;
	Map<Integer, WasmName> functionNames = new HashMap<>();

	public WasmNameSection(BinaryReader reader) throws IOException {
		super(reader);
		long sectionEnd = getSectionOffset() + getSectionSize();
		while(reader.getPointerIndex() < sectionEnd) {
			readSubsection(reader);
		}
	}

	private void readSubsection(BinaryReader reader) throws IOException {
		byte sectionId = reader.readNextByte();
		long size = new Leb128(reader).getValue();
		byte[] subContents = reader.readNextByteArray((int)size);
		BinaryReader subReader = new BinaryReader(new ByteArrayProvider(subContents), true);
		switch(sectionId) {
		case 0: //module name section
			moduleName = new WasmName(subReader);
			return;
		case 2: //local name section
			//no handling yet
			return;
		case 1: //function name section
			long numAssoc = new Leb128(subReader).getValue();
			for(int i = 0; i < numAssoc; i++) {
				int idx = (int)new Leb128(subReader).getValue();
				WasmName name = new WasmName(subReader);
				functionNames.put(idx, name);
			}
			return;
		}
	}

	@Override
	protected void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		super.addToStructure(structure);
	}
	
	public String getFunctionName(int idx) {
		WasmName name = functionNames.getOrDefault(idx, null);
		if(name == null)
			return null;
		return name.getValue();
	}

	@Override
	public String getName() {
		return ".name";
	}
}
