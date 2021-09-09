package wasm.format.sections;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;

public abstract class WasmSection implements StructConverter {
	
	private WasmSectionId id;
	private LEB128 contentLength;
	private long sectionOffset;

	public enum WasmSectionId {
		SEC_CUSTOM,
		SEC_TYPE,
		SEC_IMPORT,
		SEC_FUNCTION,
		SEC_TABLE,
		SEC_LINEARMEMORY,
		SEC_GLOBAL,
		SEC_EXPORT,
		SEC_START,
		SEC_ELEMENT,
		SEC_CODE,
		SEC_DATA
	}
	
	public static WasmSection createSection(BinaryReader reader) throws IOException {
		long sectionOffset = reader.getPointerIndex();
		int id = reader.readNextUnsignedByte();
		LEB128 contentLength = LEB128.readUnsignedValue(reader);
		reader.setPointerIndex(reader.getPointerIndex() + contentLength.asLong());

		if(id >= WasmSectionId.values().length)
			return null;

		BinaryReader sectionReader = reader.clone(sectionOffset);

		switch (WasmSectionId.values()[id]) {
			case SEC_CUSTOM:
				return WasmCustomSection.create(sectionReader);
			case SEC_TYPE:
				return new WasmTypeSection(sectionReader);
			case SEC_IMPORT:
				return new WasmImportSection(sectionReader);
			case SEC_FUNCTION:
				return new WasmFunctionSection(sectionReader);
			case SEC_TABLE:
				return new WasmTableSection(sectionReader);
			case SEC_LINEARMEMORY:
				return new WasmLinearMemorySection(sectionReader);
			case SEC_GLOBAL:
				return new WasmGlobalSection(sectionReader);
			case SEC_EXPORT:
				return new WasmExportSection(sectionReader);
			case SEC_START:
				return new WasmStartSection(sectionReader);
			case SEC_ELEMENT:
				return new WasmElementSection(sectionReader);
			case SEC_CODE:
				return new WasmCodeSection(sectionReader);
			case SEC_DATA:
				return new WasmDataSection(sectionReader);
			default:
				return null;
		}
	}
	
	protected WasmSection(BinaryReader reader) throws IOException {
		sectionOffset = reader.getPointerIndex();
		id = WasmSectionId.values()[reader.readNextUnsignedByte()];
		contentLength = LEB128.readUnsignedValue(reader);
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder(getName());
		builder.add(BYTE, "id");
		builder.add(contentLength, "size");
		addToStructure(builder);
		return builder.toStructure();
	}
	
	public abstract String getName();

	protected abstract void addToStructure(StructureBuilder builder) throws DuplicateNameException, IOException;

	public WasmSectionId getId() {
		return id;
	}

	public long getSectionOffset() {
		return sectionOffset;
	}

	public long getContentSize() {
		return contentLength.asLong();
	}

	public long getSectionSize() {
		return 1 + contentLength.getLength() + contentLength.asLong();
	}
}
