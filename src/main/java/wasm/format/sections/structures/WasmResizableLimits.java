package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureUtils;

public class WasmResizableLimits implements StructConverter {

	private int flags;
	private LEB128 initial;
	private LEB128 maximum;

	public WasmResizableLimits(BinaryReader reader) throws IOException {
		flags = reader.readNextUnsignedByte();
		initial = LEB128.readUnsignedValue(reader);
		if (flags == 1) {
			maximum = LEB128.readUnsignedValue(reader);
		}
	}

	public long getInitial() {
		return initial.asLong();
	}

	public long getMaximum() {
		if (maximum != null) {
			return maximum.asLong();
		}
		return -1;
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
