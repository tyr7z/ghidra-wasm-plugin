package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;
import wasm.format.StructureUtils;

public abstract class WasmNameSubsection implements StructConverter {

	protected int id;
	private Leb128 contentLength;
	private long sectionOffset;

	public enum WasmNameSubsectionId {
		NAME_MODULE,
		NAME_FUNCTION,
		NAME_LOCAL
	}

	public static WasmNameSubsection createSubsection(BinaryReader reader) throws IOException {
		long sectionOffset = reader.getPointerIndex();
		int id = reader.readNextUnsignedByte();
		Leb128 contentLength = new Leb128(reader);
		reader.setPointerIndex(reader.getPointerIndex() + contentLength.getValue());

		BinaryReader sectionReader = reader.clone(sectionOffset);

		if (id >= WasmNameSubsectionId.values().length) {
			return new WasmNameUnknownSubsection(sectionReader);
		}

		switch (WasmNameSubsectionId.values()[id]) {
		case NAME_MODULE:
			return new WasmNameModuleSubsection(sectionReader);
		case NAME_FUNCTION:
			return new WasmNameFunctionSubsection(sectionReader);
		case NAME_LOCAL:
			return new WasmNameLocalSubsection(sectionReader);
		default:
			return null;
		}
	}

	protected WasmNameSubsection(BinaryReader reader) throws IOException {
		sectionOffset = reader.getPointerIndex();
		id = reader.readNextUnsignedByte();
		contentLength = new Leb128(reader);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = StructureUtils.createStructure(getName());
		StructureUtils.addField(structure, BYTE, "id");
		StructureUtils.addField(structure, contentLength, "size");
		addToStructure(structure);
		return structure;
	}

	public abstract String getName();

	protected abstract void addToStructure(Structure s) throws IllegalArgumentException, DuplicateNameException, IOException;

	public WasmNameSubsectionId getId() {
		if (id < WasmNameSubsectionId.values().length) {
			return WasmNameSubsectionId.values()[id];
		}
		return null;
	}

	public long getSectionOffset() {
		return sectionOffset;
	}

	public long getContentSize() {
		return contentLength.getValue();
	}

	public long getSectionSize() {
		return 1 + contentLength.getSize() + contentLength.getValue();
	}
}
