package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureUtils;

public class WasmElementSegment implements StructConverter {

	public WasmElementSegment(BinaryReader reader) throws IOException {
		int mode = reader.readNextUnsignedByte();
		/* TODO */
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = StructureUtils.createStructure("element_segment");
		StructureUtils.addField(structure, BYTE, "mode");
		return structure;
	}
}
