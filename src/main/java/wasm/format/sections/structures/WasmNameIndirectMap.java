package wasm.format.sections.structures;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureUtils;

public class WasmNameIndirectMap implements StructConverter {
	private LEB128 count;
	private List<WasmIndirectAssoc> entries = new ArrayList<>();
	private Map<Long, WasmNameMap> map = new HashMap<>();

	private static class WasmIndirectAssoc {
		LEB128 idx;
		WasmNameMap nameMap;
	}

	public WasmNameIndirectMap(BinaryReader reader) throws IOException {
		count = LEB128.readUnsignedValue(reader);
		for (int i = 0; i < count.asLong(); i++) {
			WasmIndirectAssoc assoc = new WasmIndirectAssoc();
			assoc.idx = LEB128.readUnsignedValue(reader);
			assoc.nameMap = new WasmNameMap(reader);
			entries.add(assoc);
			map.put(assoc.idx.asLong(), assoc.nameMap);
		}
	}

	public String getEntry(long idx1, long idx2) {
		WasmNameMap subMap = map.get(idx1);
		if (subMap == null)
			return null;

		return subMap.getEntry(idx2);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = StructureUtils.createStructure("indirectnamemap");
		StructureUtils.addField(structure, count, "count");
		for (int i = 0; i < entries.size(); i++) {
			WasmIndirectAssoc assoc = entries.get(i);
			StructureUtils.addField(structure, assoc.idx, "idx" + i);
			StructureUtils.addField(structure, assoc.nameMap, "namemap" + i);
		}
		return structure;
	}
}
