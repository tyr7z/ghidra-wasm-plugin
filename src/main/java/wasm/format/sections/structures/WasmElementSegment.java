package wasm.format.sections.structures;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.WasmLoader;
import wasm.format.StructureUtils;
import wasm.format.WasmEnums.ValType;
import wasm.format.WasmModule;

public class WasmElementSegment implements StructConverter {

	private int flags;
	private ElementSegmentMode mode;

	private LEB128 tableidx; /* if (flags & 3) == 2 */
	private ConstantExpression offset; /* if (flags & 1) == 0 */
	private LEB128 count;

	int elemkind; /* if (flags & 4) == 0 */
	private List<LEB128> funcidxs; /* if (flags & 4) == 0 */

	ValType elemtype; /* if (flags & 4) != 0 */
	private List<ConstantExpression> exprs; /* if (flags & 4) != 0 */

	public enum ElementSegmentMode {
		active,
		passive,
		declarative,
	}

	public WasmElementSegment(BinaryReader reader) throws IOException {
		flags = reader.readNextUnsignedByte();
		if ((flags & 3) == 2) {
			/* active segment with explicit table index */
			tableidx = LEB128.readUnsignedValue(reader);
		} else {
			/* tableidx defaults to 0 */
			tableidx = null;
		}

		if ((flags & 1) == 0) {
			/* active segment */
			mode = ElementSegmentMode.active;
			offset = new ConstantExpression(reader);
		} else if ((flags & 2) == 0) {
			mode = ElementSegmentMode.passive;
		} else {
			mode = ElementSegmentMode.declarative;
		}

		if ((flags & 3) == 0) {
			/* implicit element type */
			elemkind = 0;
			elemtype = ValType.funcref;
		} else {
			/* explicit element type */
			int typeCode = reader.readNextUnsignedByte();
			if ((flags & 4) == 0) {
				/* elemkind */
				elemkind = typeCode;
			} else {
				/* reftype */
				elemtype = ValType.fromByte(typeCode);
			}
		}

		count = LEB128.readUnsignedValue(reader);
		if ((flags & 4) == 0) {
			/* vector of funcidx */
			funcidxs = new ArrayList<>();
			for (int i = 0; i < count.asLong(); i++) {
				funcidxs.add(LEB128.readUnsignedValue(reader));
			}
		} else {
			/* vector of expr */
			exprs = new ArrayList<>();
			for (int i = 0; i < count.asLong(); i++) {
				exprs.add(new ConstantExpression(reader));
			}
		}
	}

	public ElementSegmentMode getMode() {
		return mode;
	}

	public long getTableIndex() {
		if (tableidx == null) {
			return 0;
		}
		return tableidx.asLong();
	}

	public Long getOffset() {
		if (offset == null) {
			return null;
		}
		return offset.asI32();
	}

	public ValType getElementType() {
		if ((flags & 4) == 0) {
			if (elemkind == 0) {
				return ValType.funcref;
			}
			return null;
		} else {
			return elemtype;
		}
	}

	public Long[] getAddresses(WasmModule module) {
		int count = (int) this.count.asLong();
		Long[] result = new Long[count];

		if (funcidxs != null) {
			for (int i = 0; i < count; i++) {
				long funcidx = funcidxs.get(i).asLong();
				result[i] = WasmLoader.getFunctionAddress(module, (int) funcidx);
			}
			return result;
		}

		if (exprs != null) {
			for (int i = 0; i < count; i++) {
				result[i] = exprs.get(i).asReference(module);
			}
			return result;
		}
		return null;
	}

	public byte[] getInitData(WasmModule module) {
		int count = (int) this.count.asLong();
		byte[] result = new byte[count * 8];
		Arrays.fill(result, (byte) 0xff);

		if (funcidxs != null) {
			for (int i = 0; i < count; i++) {
				long funcidx = funcidxs.get(i).asLong();
				long funcaddr = WasmLoader.getFunctionAddress(module, (int) funcidx);
				byte[] v = ConstantExpression.longToBytes(funcaddr);
				System.arraycopy(v, 0, result, i * 8, 8);
			}
			return result;
		}

		if (exprs != null) {
			for (int i = 0; i < count; i++) {
				byte[] v = exprs.get(i).asBytes(module);
				if (v != null)
					System.arraycopy(v, 0, result, i * 8, 8);
			}
			return result;
		}
		return null;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = StructureUtils.createStructure("element_segment");
		StructureUtils.addField(structure, BYTE, "flags");
		if (tableidx != null) {
			StructureUtils.addField(structure, tableidx, "tableidx");
		}
		if (offset != null) {
			StructureUtils.addField(structure, offset, "offset");
		}
		if ((flags & 3) != 0) {
			/* both elemkind and reftype are single bytes */
			StructureUtils.addField(structure, BYTE, "element_type");
		}

		StructureUtils.addField(structure, count, "count");
		if (funcidxs != null) {
			for (int i = 0; i < funcidxs.size(); i++) {
				StructureUtils.addField(structure, funcidxs.get(i), "element" + i);
			}
		}
		if (exprs != null) {
			for (int i = 0; i < exprs.size(); i++) {
				StructureUtils.addField(structure, exprs.get(i), "element" + i);
			}
		}

		return structure;
	}
}
