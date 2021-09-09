package wasm.format;

import java.io.IOException;
import java.util.Arrays;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

public class WasmHeader implements StructConverter {

	private byte[] magic;
	private int version;

	public WasmHeader(BinaryReader reader) throws IOException {
		magic = reader.readNextByteArray(WasmConstants.WASM_MAGIC.length);
		version = reader.readNextInt();
		if (!Arrays.equals(WasmConstants.WASM_MAGIC, magic)) {
			throw new IOException("not a wasm file.");
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder("header");
		builder.add(STRING, 4, "magic");
		builder.add(DWORD, 4, "version");
		return builder.toStructure();
	}

	public byte[] getMagic() {
		return magic;
	}

	public int getVersion() {
		return version;
	}
}
