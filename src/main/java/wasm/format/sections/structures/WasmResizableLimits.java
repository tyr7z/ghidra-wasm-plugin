package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;
import wasm.format.StructureUtils;

public class WasmResizableLimits implements StructConverter {

	private int flags;
	private Leb128 initial;
	private Leb128 maximum;

	public WasmResizableLimits(BinaryReader reader) throws IOException {
		flags = reader.readNextUnsignedByte();
		initial = new Leb128(reader);
		if (flags == 1) {
			maximum = new Leb128(reader);
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = StructureUtils.createStructure("limits");
		StructureUtils.addField(structure, BYTE, "flags");
		StructureUtils.addField(structure, initial, "initial");
		if (maximum != null) {
			StructureUtils.addField(structure, maximum, "maximum");
		}
		return structure;
	}
}
