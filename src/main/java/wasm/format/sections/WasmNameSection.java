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
	Map<Integer, Map<Integer, WasmName>> localNames = new HashMap<>();

	public WasmNameSection(BinaryReader reader) throws IOException {
		super(reader);
		long sectionEnd = getSectionOffset() + getSectionSize();
		while(reader.getPointerIndex() < sectionEnd) {
			readSubsection(reader);
		}
	}

	private static Map<Integer, WasmName> readNameMap(BinaryReader reader) throws IOException {
		Map<Integer, WasmName> map = new HashMap<>();
		long count = new Leb128(reader).getValue();
		for(int i = 0; i < count; i++) {
			int idx = (int)new Leb128(reader).getValue();
			WasmName name = new WasmName(reader);
			map.put(idx, name);
		}
		return map;
	}

	private static Map<Integer, Map<Integer, WasmName>> readIndirectNameMap(BinaryReader reader) throws IOException {
		Map<Integer, Map<Integer, WasmName>> map = new HashMap<>();
		long count = new Leb128(reader).getValue();
		for(int i = 0; i < count; i++) {
			int idx = (int)new Leb128(reader).getValue();
			Map<Integer, WasmName> subMap = readNameMap(reader);
			map.put(idx, subMap);
		}
		return map;
	}

	private void readSubsection(BinaryReader reader) throws IOException {
		byte sectionId = reader.readNextByte();
		long size = new Leb128(reader).getValue();
		byte[] subContents = reader.readNextByteArray((int)size);
		BinaryReader subReader = new BinaryReader(new ByteArrayProvider(subContents), true);
		switch(sectionId) {
		case 0: //module name section
			moduleName = new WasmName(subReader);
			break;
		case 1: //function name section
			functionNames = readNameMap(subReader);
			break;
		case 2: //local name section
			localNames = readIndirectNameMap(subReader);
			break;
		}
	}

	@Override
	protected void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		super.addToStructure(structure);
		/* TODO */
	}

	public String getModuleName() {
		return moduleName.getValue();
	}

	public String getFunctionName(int idx) {
		WasmName result = functionNames.get(idx);
		if(result == null)
			return null;
		return result.getValue();
	}

	public String getLocalName(int funcidx, int localidx) {
		Map<Integer, WasmName> localMap = localNames.get(funcidx);
		if(localMap == null)
			return null;
		WasmName result = localMap.get(localidx);
		if(result == null)
			return null;
		return result.getValue();
	}

	@Override
	public String getName() {
		return ".name";
	}
}
