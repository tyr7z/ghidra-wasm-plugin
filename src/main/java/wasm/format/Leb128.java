/* ###
 * IP: Apache License 2.0
 */
/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package wasm.format;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

public final class Leb128 implements StructConverter {
	private long value;
	private int length;

	public Leb128(BinaryReader reader) throws IOException {
		value = 0;
		length = 0;

		int cur;
		do {
			cur = reader.readNextUnsignedByte();
			value |= (cur & 0x7f) << (length * 7);
			length++;
		} while ((cur & 0x80) == 0x80);
	}

	public long getSignedValue() {
		long signbit = 1 << (7 * length - 1);
		if ((value & signbit) != 0) {
			return value - (signbit << 1);
		}
		return value;
	}

	public long getValue() {
		return value;
	}

	public int getSize() {
		return length;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		switch (length) {
		case 1:
			return ghidra.app.util.bin.StructConverter.BYTE;
		case 2:
			return ghidra.app.util.bin.StructConverter.WORD;
		case 4:
			return ghidra.app.util.bin.StructConverter.DWORD;
		}
		return new ArrayDataType(BYTE, length, BYTE.getLength());
	}
}
