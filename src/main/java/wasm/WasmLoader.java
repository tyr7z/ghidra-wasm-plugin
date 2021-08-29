/* ###
 * IP: GHIDRA
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
package wasm;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import wasm.format.WasmConstants;
import wasm.format.WasmEnums.WasmExternalKind;
import wasm.format.WasmHeader;
import wasm.format.WasmModule;
import wasm.format.sections.WasmCodeSection;
import wasm.format.sections.WasmDataSection;
import wasm.format.sections.WasmElementSection;
import wasm.format.sections.WasmExportSection;
import wasm.format.sections.WasmGlobalSection;
import wasm.format.sections.WasmImportSection;
import wasm.format.sections.WasmLinearMemorySection;
import wasm.format.sections.WasmNameSection;
import wasm.format.sections.WasmSection;
import wasm.format.sections.WasmTableSection;
import wasm.format.sections.structures.WasmDataSegment;
import wasm.format.sections.structures.WasmElementSegment;
import wasm.format.sections.structures.WasmExportEntry;
import wasm.format.sections.structures.WasmFunctionBody;
import wasm.format.sections.structures.WasmGlobalEntry;
import wasm.format.sections.structures.WasmImportEntry;
import wasm.format.sections.structures.WasmResizableLimits;
import wasm.format.sections.structures.WasmTableType;

public class WasmLoader extends AbstractLibrarySupportLoader {

	public final static long HEADER_BASE = 0x10000000;
	public final static long METHOD_ADDRESS = 0x20000000;
	public final static long MODULE_BASE = 0x30000000;
	public final static long IMPORTS_BASE = 0x40000000;
	// ^ this must be later than METHOD_ADDRESS since we assume that
	// program.getFunctions(true) returns non-imported functions first
	public final static long IMPORT_STUB_LEN = 16;

	@Override
	public String getName() {
		return "WebAssembly";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);
		WasmHeader header = new WasmHeader(reader);

		if (Arrays.equals(WasmConstants.WASM_MAGIC, header.getMagic()) && WasmConstants.WASM_VERSION == header.getVersion()) {
			loadSpecs.add(new LoadSpec(this, 0x10000000, new LanguageCompilerSpecPair("Wasm:LE:32:default", "default"), true));
		}

		return loadSpecs;
	}

	public static Address getMemoryAddress(Program program, long memIdx, long offset) {
		if (memIdx != 0) {
			throw new IllegalArgumentException("non-zero memIdx is not supported");
		}

		return program.getAddressFactory().getAddressSpace("mem0").getAddress(offset);
	}

	public static Address getMethodAddress(Program program, long fileOffset) {
		return getProgramAddress(program, METHOD_ADDRESS + fileOffset);
	}

	public static Address getImportAddress(Program program, long funcIdx) {
		return getProgramAddress(program, IMPORTS_BASE + IMPORT_STUB_LEN * funcIdx);
	}

	public static Address getGlobalAddress(Program program, long globalIdx) {
		return program.getAddressFactory().getAddressSpace("global").getAddress(globalIdx * 8);
	}

	public static Address getTableAddress(Program program, long tableIdx, long offsetIdx) {
		return program.getAddressFactory().getAddressSpace("table").getAddress((tableIdx << 32) + (offsetIdx * 8));
	}

	private static Address getProgramAddress(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	public static Long getFunctionAddress(WasmModule module, int funcIdx) {
		WasmImportSection importSection = module.getImportSection();
		if (importSection != null) {
			List<WasmImportEntry> imports = importSection.getEntries();
			if (funcIdx < imports.size()) {
				return IMPORTS_BASE + IMPORT_STUB_LEN * funcIdx;
			} else {
				funcIdx -= imports.size();
			}
		}

		WasmCodeSection codeSection = module.getCodeSection();
		if (codeSection != null) {
			List<WasmFunctionBody> methods = codeSection.getFunctions();
			if (funcIdx < methods.size()) {
				return METHOD_ADDRESS + methods.get(funcIdx).getOffset();
			}
		}
		return null;
	}

	public static Data createData(Program program, Listing listing, Address address, DataType dt) {
		try {
			Data d = listing.getDataAt(address);
			if (d == null || !dt.isEquivalent(d.getDataType())) {
				d = DataUtilities.createData(program, address, dt, -1, false,
						ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
			return d;
		} catch (CodeUnitInsertionException e) {
			Msg.warn(WasmLoader.class, "Data markup conflict at " + address, e);
		} catch (DataTypeConflictException e) {
			Msg.error(WasmLoader.class, "Data type markup conflict:" + e.getMessage(), e);
		}
		return null;
	}

	private void createModuleBlock(Program program, FileBytes fileBytes) {
		Address start = getProgramAddress(program, MODULE_BASE);
		try {
			MemoryBlock block = program.getMemory().createInitializedBlock(".module", start, fileBytes, 0, fileBytes.getSize(), false);
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(false);
			block.setSourceName("Wasm Module");
			block.setComment("The full file contents of the Wasm module");
		} catch (Exception e) {
			Msg.error(this, "Failed to create .module block", e);
		}
	}

	private void createHeaderBlock(Program program, FileBytes fileBytes, WasmHeader header) {
		Address start = getProgramAddress(program, HEADER_BASE);
		try {
			MemoryBlock block = program.getMemory().createInitializedBlock(".header", start, fileBytes, 0, 8, false);
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(false);
			block.setSourceName("Wasm Module");
			createData(program, program.getListing(), start, header.toDataType());
		} catch (Exception e) {
			Msg.error(this, "Failed to create .header block", e);
		}
	}

	private void createSectionBlock(Program program, FileBytes fileBytes, WasmSection section) {
		Address start = getProgramAddress(program, HEADER_BASE + section.getSectionOffset());
		try {
			MemoryBlock block = program.getMemory().createInitializedBlock(section.getName(), start, fileBytes, section.getSectionOffset(), section.getSectionSize(), false);
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(false);
			block.setSourceName("Wasm Section");
			createData(program, program.getListing(), start, section.toDataType());
		} catch (Exception e) {
			Msg.error(this, "Failed to create " + section.getName() + " block", e);
		}
	}

	private void createFunctionBodyBlock(Program program, FileBytes fileBytes, String functionName, long offset, long length) throws Exception {
		Address start = getProgramAddress(program, METHOD_ADDRESS + offset);
		MemoryBlock block = program.getMemory().createInitializedBlock(functionName, start, fileBytes, offset, length, false);
		block.setRead(true);
		block.setWrite(false);
		block.setExecute(true);
		block.setSourceName("Wasm Function");
	}

	private void createImportStubBlock(Program program, long length) throws Exception {
		Address address = getProgramAddress(program, IMPORTS_BASE);
		MemoryBlock block = program.getMemory().createUninitializedBlock(MemoryBlock.EXTERNAL_BLOCK_NAME, address, length, false);
		block.setRead(true);
		block.setWrite(false);
		block.setExecute(true);
		block.setComment("NOTE: This block is artificial and is used to represent imported functions");
	}

	/**
	 * Delete any overlapping portions of an existing memory block.
	 * 
	 * @param program
	 * @param startAddress
	 *            First address to clear, inclusive
	 * @param endAddress
	 *            Last address to clear, inclusive
	 * @param monitor
	 * @throws Exception
	 */
	private void removeOverlappingMemory(Program program, Address startAddress, Address endAddress, TaskMonitor monitor) throws Exception {
		Memory memory = program.getMemory();

		/* Delete any overlapping portions of an existing block */
		MemoryBlock b1 = memory.getBlock(startAddress);
		if (b1 != null && !b1.getStart().equals(startAddress)) {
			String b1name = b1.getName();
			memory.split(b1, startAddress);
			/* remove automatically-added ".split" suffix */
			memory.getBlock(startAddress).setName(b1name);
		}

		MemoryBlock b2 = memory.getBlock(endAddress);
		if (b2 != null && !b2.getEnd().equals(endAddress)) {
			String b2name = b1.getName();
			memory.split(b2, endAddress.add(1));
			memory.getBlock(endAddress.add(1)).setName(b2name);
		}

		MemoryBlock toDelete = memory.getBlock(startAddress);
		if (toDelete != null) {
			memory.removeBlock(toDelete, monitor);
		}
	}

	private String getMethodName(WasmNameSection names, WasmExportSection exports, int id) {
		if (names != null) {
			String name = names.getFunctionName(id);
			if (name != null) {
				return "wasm_" + name;
			}
		}

		if (exports != null) {
			WasmExportEntry entry = exports.findMethod(id);
			if (entry != null) {
				return "export_" + entry.getName();
			}
		}
		return "unnamed_function_" + id;
	}

	private void loadCodeSection(Program program, FileBytes fileBytes, WasmModule module, WasmCodeSection codeSection, TaskMonitor monitor) throws Exception {
		if (codeSection == null)
			return;

		// The function index space begins with an index for each imported function,
		// in the order the imports appear in the Import Section, if present,
		// followed by an index for each function in the Function Section,
		WasmImportSection imports = module.getImportSection();
		int importsOffset = imports == null ? 0 : imports.getCount();
		WasmExportSection exports = module.getExportSection();

		List<WasmFunctionBody> functions = codeSection.getFunctions();
		for (int codeIdx = 0; codeIdx < functions.size(); ++codeIdx) {
			WasmFunctionBody method = functions.get(codeIdx);

			String methodName = getMethodName(module.getNameSection(), exports, codeIdx + importsOffset);

			long methodOffset = method.getOffset();

			try {
				createFunctionBodyBlock(program, fileBytes, methodName, methodOffset, method.getInstructions().length);
				Address methodAddress = getMethodAddress(program, methodOffset);
				Address methodEnd = getMethodAddress(program, methodOffset + method.getInstructions().length);

				program.getFunctionManager().createFunction(
						methodName, methodAddress,
						new AddressSet(methodAddress, methodEnd), SourceType.IMPORTED);
				program.getSymbolTable().createLabel(methodAddress, methodName, SourceType.IMPORTED);
			} catch (Exception e) {
				Msg.error(this, "Failed to load function " + methodName, e);
			}
		}
	}

	private void loadMemorySection(Program program, FileBytes fileBytes, WasmLinearMemorySection memorySection, TaskMonitor monitor) throws Exception {
		if (memorySection == null)
			return;

		List<WasmResizableLimits> memories = memorySection.getMemories();
		/* only handle memory 0 for now */
		if (memories.size() > 0) {
			WasmResizableLimits mem0 = memories.get(0);
			long byteSize = mem0.getInitial() * 65536;
			Address dataStart = getMemoryAddress(program, 0, 0);
			MemoryBlock block = program.getMemory().createUninitializedBlock(".mem0", dataStart, byteSize, false);
			block.setRead(true);
			block.setWrite(true);
			block.setExecute(false);
		}
	}

	private void loadDataSection(Program program, FileBytes fileBytes, WasmDataSection dataSection, TaskMonitor monitor) throws Exception {
		if (dataSection == null)
			return;

		List<WasmDataSegment> dataSegments = dataSection.getSegments();
		for (int dataIdx = 0; dataIdx < dataSegments.size(); dataIdx++) {
			WasmDataSegment dataSegment = dataSegments.get(dataIdx);
			Long offset = dataSegment.getOffset();
			if (offset == null)
				continue;
			if (dataSegment.getIndex() != 0)
				continue;
			Address dataStart = getMemoryAddress(program, dataSegment.getIndex(), offset);
			removeOverlappingMemory(program, dataStart, dataStart.add(dataSegment.getSize() - 1), monitor);

			MemoryBlock block = program.getMemory().createInitializedBlock(".data" + dataIdx, dataStart, fileBytes, dataSegment.getFileOffset(), dataSegment.getSize(), false);
			/* We have to assume that linear memory is writable */
			block.setRead(true);
			block.setWrite(true);
			block.setExecute(false);
		}
	}

	private void loadImportSection(Program program, FileBytes fileBytes, WasmImportSection importSection, TaskMonitor monitor) throws Exception {
		if (importSection == null)
			return;

		createImportStubBlock(program, importSection.getCount() * IMPORT_STUB_LEN);
		int nextFuncIdx = 0;
		for (WasmImportEntry entry : importSection.getEntries()) {
			if (entry.getKind() != WasmExternalKind.EXT_FUNCTION) {
				continue;
			}

			String methodName = "import__" + entry.getName();
			Address methodAddress = getImportAddress(program, nextFuncIdx);
			Address methodEnd = methodAddress.add(IMPORT_STUB_LEN - 1);

			program.getFunctionManager().createFunction(
					methodName, methodAddress,
					new AddressSet(methodAddress, methodEnd), SourceType.IMPORTED);

			program.getSymbolTable().createLabel(methodAddress, methodName, SourceType.IMPORTED);

			nextFuncIdx++;
		}
	}

	private void loadGlobalSection(Program program, FileBytes fileBytes, WasmModule module, WasmGlobalSection globalSection, TaskMonitor monitor) throws Exception {
		if (globalSection == null)
			return;

		List<WasmGlobalEntry> entries = globalSection.getEntries();
		for (int globalIdx = 0; globalIdx < entries.size(); globalIdx++) {
			WasmGlobalEntry entry = entries.get(globalIdx);
			MemoryBlock block;
			Address dataStart = getGlobalAddress(program, globalIdx);

			DataType dataType = entry.getDataType();
			byte[] initBytes = entry.asBytes(module);
			if (initBytes == null) {
				block = program.getMemory().createUninitializedBlock("global" + globalIdx, dataStart, dataType.getLength(), false);
			} else {
				block = program.getMemory().createInitializedBlock("global" + globalIdx, dataStart, dataType.getLength(), (byte) 0xff, monitor, false);
				program.getMemory().setBytes(dataStart, initBytes);
			}
			block.setRead(true);
			block.setWrite(entry.isMutable());
			block.setExecute(false);
			createData(program, program.getListing(), dataStart, dataType);
			program.getSymbolTable().createLabel(dataStart, "global" + globalIdx, SourceType.IMPORTED);

			Long ref = entry.asReference(module);
			if (ref != null) {
				Address refAddr = getProgramAddress(program, ref);
				program.getReferenceManager().removeAllReferencesFrom(dataStart);
				program.getReferenceManager().addMemoryReference(dataStart, refAddr, RefType.DATA, SourceType.IMPORTED, 0);
			}
		}
	}

	private void loadTableSection(Program program, FileBytes fileBytes, WasmTableSection tableSection, TaskMonitor monitor) throws Exception {
		if (tableSection == null)
			return;

		List<WasmTableType> tables = tableSection.getTables();
		for (int tableIdx = 0; tableIdx < tables.size(); tableIdx++) {
			WasmTableType table = tables.get(tableIdx);
			DataType dataType = table.getElementDataType();

			long numElements = table.getLimits().getInitial();
			long byteSize = 8 * numElements;
			Address dataStart = getTableAddress(program, tableIdx, 0);
			MemoryBlock block = program.getMemory().createInitializedBlock(".table" + tableIdx, dataStart, byteSize, (byte) 0xff, monitor, false);
			block.setRead(true);
			block.setWrite(true);
			block.setExecute(false);
			createData(program, program.getListing(), dataStart, new ArrayDataType(dataType, (int) numElements, dataType.getLength()));
			program.getSymbolTable().createLabel(dataStart, "table" + tableIdx, SourceType.IMPORTED);
		}
	}

	private void loadElementSection(Program program, FileBytes fileBytes, WasmModule module, WasmElementSection elementSection, TaskMonitor monitor) throws Exception {
		if (elementSection == null)
			return;

		List<WasmElementSegment> entries = elementSection.getSegments();
		for (int entryIdx = 0; entryIdx < entries.size(); entryIdx++) {
			WasmElementSegment entry = entries.get(entryIdx);

			Long offset = entry.getOffset();
			if (offset == null)
				continue;

			byte[] initBytes = entry.getInitData(module);
			if (initBytes == null)
				continue;

			Address dataStart = getTableAddress(program, entry.getTableIndex(), offset);
			try {
				program.getMemory().setBytes(dataStart, initBytes);
			} catch (Exception e) {
				Msg.error(this, "Failed to process element segment " + entryIdx, e);
			}

			Long[] refs = entry.getAddresses(module);
			for (int i = 0; i < refs.length; i++) {
				if (refs[i] != null) {
					Address refAddr = getProgramAddress(program, refs[i]);
					Address elementAddr = dataStart.add(i * 8);
					program.getReferenceManager().removeAllReferencesFrom(elementAddr);
					program.getReferenceManager().addMemoryReference(elementAddr, refAddr, RefType.DATA, SourceType.IMPORTED, 0);
				}
			}
		}
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log) throws IOException {

		monitor.setMessage("Wasm Loader: Start loading");

		try {
			doLoad(provider, program, monitor);
		} catch (Exception e) {
			monitor.setMessage("Wasm Loader: Error");
			Msg.error(this, "Failed to load Wasm module", e);
		}
	}

	private void doLoad(ByteProvider provider, Program program, TaskMonitor monitor) throws Exception {
		BinaryReader reader = new BinaryReader(provider, true);
		WasmModule module = new WasmModule(reader);

		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, 0, provider.length(), monitor);

		createModuleBlock(program, fileBytes);
		createHeaderBlock(program, fileBytes, module.getHeader());

		for (WasmSection section : module.getSections()) {
			monitor.setMessage("Wasm Loader: Loading section " + section.getId().toString());
			createSectionBlock(program, fileBytes, section);
		}

		loadMemorySection(program, fileBytes, module.getLinearMemorySection(), monitor);
		loadDataSection(program, fileBytes, module.getDataSection(), monitor);
		loadCodeSection(program, fileBytes, module, module.getCodeSection(), monitor);
		loadImportSection(program, fileBytes, module.getImportSection(), monitor);
		loadGlobalSection(program, fileBytes, module, module.getGlobalSection(), monitor);
		loadTableSection(program, fileBytes, module.getTableSection(), monitor);
		loadElementSection(program, fileBytes, module, module.getElementSection(), monitor);
	}
}
