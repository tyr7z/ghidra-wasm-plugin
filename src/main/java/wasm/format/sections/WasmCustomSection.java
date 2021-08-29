package wasm.format.sections;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureUtils;
import wasm.format.sections.structures.WasmName;

public abstract class WasmCustomSection extends WasmSection {
	private WasmName name;
	private long customLength;

	protected WasmCustomSection(BinaryReader reader) throws IOException {
		super(reader);
		name = new WasmName(reader);
		customLength = getContentSize() - name.getSize();
	}

	public static WasmCustomSection create(BinaryReader reader) throws IOException {
		long initialOffset = reader.getPointerIndex();
		/* skip section header: id + contentLength */
		reader.readNextUnsignedByte();
		LEB128.readUnsignedValue(reader);

		String name = new WasmName(reader).getValue();
		reader.setPointerIndex(initialOffset);

		if (name.equals("name")) {
			return new WasmNameSection(reader);
		}

		return new WasmUnknownCustomSection(reader);
	}

	@Override
	protected void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		StructureUtils.addField(structure, name, "name");
	}

	public String getCustomName() {
		return name.getValue();
	}

	public long getCustomSize() {
		return customLength;
	}
}
