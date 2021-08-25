package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureUtils;

public class WasmTableType implements StructConverter {

	private byte elementType;
	private WasmResizableLimits limits;

	public WasmTableType(BinaryReader reader) throws IOException {
		elementType = reader.readNextByte();
		limits = new WasmResizableLimits(reader);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = StructureUtils.createStructure("table_type");
		StructureUtils.addField(structure, BYTE, "element_type");
		StructureUtils.addField(structure, limits, "limits");
		return structure;
	}
}
