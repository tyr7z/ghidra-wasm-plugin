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
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import wasm.format.WasmConstants;
import wasm.format.WasmEnums.WasmExternalKind;
import wasm.format.WasmHeader;
import wasm.format.WasmModule;
import wasm.format.sections.WasmNameSection;
import wasm.format.sections.WasmSection;
import wasm.format.sections.structures.WasmDataSegment;
import wasm.format.sections.structures.WasmElementSegment;
import wasm.format.sections.structures.WasmExportEntry;
import wasm.format.sections.structures.WasmFunctionBody;
import wasm.format.sections.structures.WasmGlobalEntry;
import wasm.format.sections.structures.WasmGlobalType;
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
	// Addresses for the raw data/element segments
	public final static long DATA_BASE = 0x50000000;

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

	// #region Address computations
	public static long getFunctionAddressOffset(WasmModule module, int funcidx) {
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_FUNCTION);
		if (funcidx < imports.size()) {
			return IMPORTS_BASE + IMPORT_STUB_LEN * funcidx;
		} else {
			WasmFunctionBody functionBody = module.getNonImportedFunctionBodies().get(funcidx - imports.size());
			return METHOD_ADDRESS + functionBody.getOffset();
		}
	}

	public static Address getFunctionAddress(Program program, WasmModule module, int funcidx) {
		return getProgramAddress(program, getFunctionAddressOffset(module, funcidx));
	}

	public static long getFunctionSize(Program program, WasmModule module, int funcidx) {
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_FUNCTION);
		if (funcidx < imports.size()) {
			return IMPORT_STUB_LEN;
		} else {
			WasmFunctionBody functionBody = module.getNonImportedFunctionBodies().get(funcidx - imports.size());
			return functionBody.getInstructions().length;
		}
	}

	public static Address getTableAddress(Program program, int tableidx, long itemIndex) {
		return program.getAddressFactory().getAddressSpace("table").getAddress((((long) tableidx) << 32) + (itemIndex * 8));
	}

	public static Address getMemoryAddress(Program program, int memidx, long offset) {
		if (memidx != 0) {
			throw new IllegalArgumentException("non-zero memidx is not supported");
		}

		return program.getAddressFactory().getAddressSpace("mem0").getAddress(offset);
	}

	public static Address getGlobalAddress(Program program, int globalidx) {
		return program.getAddressFactory().getAddressSpace("global").getAddress(((long) globalidx) * 8);
	}

	private static Address getProgramAddress(Program program, long offset) {
		return program.getAddressFactory().getAddressSpace("program").getAddress(offset);
	}
	// #endregion

	// #region Naming
	private static Namespace getNamespace(Program program, Namespace parent, String name) {
		try {
			return program.getSymbolTable().getOrCreateNameSpace(parent, name, SourceType.IMPORTED);
		} catch (Exception e) {
			return parent;
		}
	}

	public static Namespace getFunctionNamespace(Program program, WasmModule module, int funcidx) {
		Namespace globalNamespace = program.getGlobalNamespace();

		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_FUNCTION);
		if (funcidx < imports.size()) {
			Namespace importNamespace = getNamespace(program, globalNamespace, "import");
			return getNamespace(program, importNamespace, imports.get(funcidx).getModule());
		}
		WasmExportEntry entry = module.findExport(WasmExternalKind.EXT_FUNCTION, funcidx);
		if (entry != null) {
			return getNamespace(program, globalNamespace, "export");
		}
		return globalNamespace;
	}

	public static String getFunctionName(WasmModule module, int funcidx) {
		WasmNameSection nameSection = module.getNameSection();
		if (nameSection != null) {
			String name = nameSection.getFunctionName(funcidx);
			if (name != null) {
				return name;
			}
		}
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_FUNCTION);
		if (funcidx < imports.size()) {
			return imports.get(funcidx).getName();
		}
		WasmExportEntry entry = module.findExport(WasmExternalKind.EXT_FUNCTION, funcidx);
		if (entry != null) {
			return entry.getName();
		}
		return "unnamed_function_" + funcidx;
	}
	// #endregion

	// #region Memory blocks
	private static Data createData(Program program, Listing listing, Address address, DataType dt) {
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

	private static void createModuleBlock(Program program, FileBytes fileBytes) {
		Address start = getProgramAddress(program, MODULE_BASE);
		try {
			MemoryBlock block = program.getMemory().createInitializedBlock(".module", start, fileBytes, 0, fileBytes.getSize(), false);
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(false);
			block.setSourceName("Wasm Module");
			block.setComment("The full file contents of the Wasm module");
		} catch (Exception e) {
			Msg.error(WasmLoader.class, "Failed to create .module block", e);
		}
	}

	private static void createHeaderBlock(Program program, FileBytes fileBytes, WasmHeader header) {
		Address start = getProgramAddress(program, HEADER_BASE);
		try {
			MemoryBlock block = program.getMemory().createInitializedBlock(".header", start, fileBytes, 0, 8, false);
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(false);
			block.setSourceName("Wasm Module");
			createData(program, program.getListing(), start, header.toDataType());
		} catch (Exception e) {
			Msg.error(WasmLoader.class, "Failed to create .header block", e);
		}
	}

	private static void createSectionBlock(Program program, FileBytes fileBytes, WasmSection section) {
		Address start = getProgramAddress(program, HEADER_BASE + section.getSectionOffset());
		String name = ".section" + section.getName();
		try {
			MemoryBlock block = program.getMemory().createInitializedBlock(name, start, fileBytes, section.getSectionOffset(), section.getSectionSize(), false);
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(false);
			block.setSourceName("Wasm Section");
			createData(program, program.getListing(), start, section.toDataType());
		} catch (Exception e) {
			Msg.error(WasmLoader.class, "Failed to create " + name + " block", e);
		}
	}

	private static void createFunctionBodyBlock(Program program, FileBytes fileBytes, int funcidx, long offset, long length) {
		Address start = getProgramAddress(program, METHOD_ADDRESS + offset);
		String name = ".function" + funcidx;
		try {
			MemoryBlock block = program.getMemory().createInitializedBlock(name, start, fileBytes, offset, length, false);
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(true);
			block.setSourceName("Wasm Function");
		} catch (Exception e) {
			Msg.error(WasmLoader.class, "Failed to create " + name + " block", e);
		}
	}

	private static void createMemoryBlock(Program program, int memidx, long length) {
		Address dataStart = getMemoryAddress(program, memidx, 0);
		try {
			MemoryBlock block = program.getMemory().createUninitializedBlock(".mem" + memidx, dataStart, length, false);
			block.setRead(true);
			block.setWrite(true);
			block.setExecute(false);
		} catch (Exception e) {
			Msg.error(WasmLoader.class, "Failed to create memory block mem" + memidx, e);
		}
	}

	private static void createImportStubBlock(Program program, long length) {
		Address address = getProgramAddress(program, IMPORTS_BASE);
		try {
			MemoryBlock block = program.getMemory().createUninitializedBlock(MemoryBlock.EXTERNAL_BLOCK_NAME, address, length, false);
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(true);
			block.setComment("NOTE: This block is artificial and is used to represent imported functions");
		} catch (Exception e) {
			Msg.error(WasmLoader.class, "Failed to create import block", e);
		}
	}

	/**
	 * Delete any overlapping portions of an existing memory block. Assumes that
	 * only one memory block overlaps the given range.
	 * 
	 * @param program
	 * @param startAddress
	 *            First address to clear, inclusive
	 * @param endAddress
	 *            Last address to clear, inclusive
	 * @param monitor
	 * @throws Exception
	 */
	private static void removeOverlappingMemory(Program program, Address startAddress, Address endAddress, TaskMonitor monitor) throws Exception {
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
	// #endregion

	private void loadFunctions(Program program, FileBytes fileBytes, WasmModule module, TaskMonitor monitor) {
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_FUNCTION);
		if (imports.size() > 0) {
			createImportStubBlock(program, imports.size() * IMPORT_STUB_LEN);
		}
		List<WasmFunctionBody> functionBodies = module.getNonImportedFunctionBodies();
		int numFunctions = imports.size() + functionBodies.size();

		for (int funcidx = 0; funcidx < numFunctions; funcidx++) {
			Address startAddress = getFunctionAddress(program, module, funcidx);
			Address endAddress = startAddress.add(getFunctionSize(program, module, funcidx) - 1);
			String functionName = getFunctionName(module, funcidx);
			Namespace functionNamespace = getFunctionNamespace(program, module, funcidx);

			if (funcidx >= imports.size()) {
				WasmFunctionBody body = functionBodies.get(funcidx - imports.size());
				createFunctionBodyBlock(program, fileBytes, funcidx, body.getOffset(), body.getInstructions().length);
			}

			try {
				program.getFunctionManager().createFunction(functionName, functionNamespace,
						startAddress, new AddressSet(startAddress, endAddress), SourceType.IMPORTED);
				program.getSymbolTable().createLabel(startAddress, functionName, functionNamespace, SourceType.IMPORTED);
			} catch (Exception e) {
				Msg.error(this, "Failed to create function index " + funcidx + "(" + functionName + ") at " + startAddress, e);
			}
		}
	}

	/**
	 * Copy element segment to table.
	 * 
	 * This is public so that it can be called after loading, e.g. to load a passive
	 * element segment once the dynamic table index and offset are known.
	 *
	 * For example, this could be called from a script as follows:
	 * 
	 * WasmLoader.loadElementsToTable(getCurrentProgram(),
	 * WasmAnalysis.getState(getCurrentProgram()).getModule(), elemidx, tableidx,
	 * offset, new ConsoleTaskMonitor())
	 */
	public static void loadElementsToTable(Program program, WasmModule module, int elemidx, int tableidx, long offset, TaskMonitor monitor) throws Exception {
		WasmElementSegment elemSegment = module.getElementSegments().get(elemidx);

		byte[] initBytes = elemSegment.getInitData(module);
		if (initBytes == null)
			return;

		Address dataStart = getTableAddress(program, tableidx, offset);
		program.getMemory().setBytes(dataStart, initBytes);

		Long[] refs = elemSegment.getAddresses(module);
		for (int i = 0; i < refs.length; i++) {
			if (refs[i] != null) {
				Address refAddr = getProgramAddress(program, refs[i]);
				Address elementAddr = dataStart.add(i * 8);
				program.getReferenceManager().removeAllReferencesFrom(elementAddr);
				program.getReferenceManager().addMemoryReference(elementAddr, refAddr, RefType.DATA, SourceType.IMPORTED, 0);
			}
		}
	}

	private void loadTables(Program program, FileBytes fileBytes, WasmModule module, TaskMonitor monitor) {
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_TABLE);
		List<WasmTableType> tables = module.getNonImportedTables();
		int numTables = imports.size() + tables.size();

		for (int tableidx = 0; tableidx < numTables; tableidx++) {
			WasmTableType table;
			if (tableidx < imports.size()) {
				table = imports.get(tableidx).getTableType();
			} else {
				table = tables.get(tableidx - imports.size());
			}

			DataType dataType = table.getElementDataType();
			long numElements = table.getLimits().getInitial();
			long byteSize = 8 * numElements;
			Address dataStart = getTableAddress(program, tableidx, 0);
			try {
				MemoryBlock block = program.getMemory().createInitializedBlock(".table" + tableidx, dataStart, byteSize, (byte) 0xff, monitor, false);
				block.setRead(true);
				block.setWrite(true);
				block.setExecute(false);
				createData(program, program.getListing(), dataStart, new ArrayDataType(dataType, (int) numElements, dataType.getLength()));
				program.getSymbolTable().createLabel(dataStart, "table" + tableidx, SourceType.IMPORTED);
			} catch (Exception e) {
				Msg.error(this, "Failed to create table " + tableidx + " at " + dataStart, e);
			}
		}

		/* Load elements */
		List<WasmElementSegment> entries = module.getElementSegments();
		for (int elemidx = 0; elemidx < entries.size(); elemidx++) {
			WasmElementSegment elemSegment = entries.get(elemidx);
			int tableidx = (int) elemSegment.getTableIndex();

			Long offset = elemSegment.getOffset();
			if (offset == null)
				continue;

			try {
				loadElementsToTable(program, module, elemidx, tableidx, offset, monitor);
			} catch (Exception e) {
				Msg.error(this, "Failed to process element segment " + elemidx, e);
			}
		}
	}

	/**
	 * Copy data segment to memory.
	 * 
	 * This is public so that it can be called after loading, e.g. to load a passive
	 * data segment once the dynamic memory index and offset are known.
	 *
	 * For example, this could be called from a script as follows:
	 * 
	 * WasmLoader.loadDataToMemory(getCurrentProgram(),
	 * WasmAnalysis.getState(getCurrentProgram()).getModule(), dataidx, memidx,
	 * offset, new ConsoleTaskMonitor())
	 */
	public static void loadDataToMemory(Program program, WasmModule module, int dataidx, int memidx, long offset, TaskMonitor monitor) throws Exception {
		WasmDataSegment dataSegment = module.getDataSegments().get(dataidx);
		MemoryBlock dataBlock = program.getMemory().getBlock(".data" + dataidx);
		FileBytes fileBytes = dataBlock.getSourceInfos().get(0).getFileBytes().get();

		Address memStart = getMemoryAddress(program, memidx, offset);
		removeOverlappingMemory(program, memStart, memStart.add(dataSegment.getSize() - 1), monitor);
		MemoryBlock block = program.getMemory().createInitializedBlock(".mem" + memidx + ".data" + dataidx, memStart, fileBytes, dataSegment.getFileOffset(), dataSegment.getSize(), false);
		block.setRead(true);
		block.setWrite(true);
		block.setExecute(false);
	}

	private void loadMemories(Program program, FileBytes fileBytes, WasmModule module, TaskMonitor monitor) {
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_MEMORY);
		List<WasmResizableLimits> memories = module.getNonImportedMemories();
		int numMemories = imports.size() + memories.size();

		for (int memidx = 0; memidx < numMemories; memidx++) {
			if (memidx > 0) {
				/* only handle memory 0 for now */
				continue;
			}
			WasmResizableLimits mem;
			if (memidx < imports.size()) {
				mem = imports.get(memidx).getMemoryType();
			} else {
				mem = memories.get(memidx - imports.size());
			}
			createMemoryBlock(program, memidx, mem.getInitial() * 65536L);
		}

		/* Load data into memory */
		List<WasmDataSegment> dataSegments = module.getDataSegments();
		for (int dataidx = 0; dataidx < dataSegments.size(); dataidx++) {
			WasmDataSegment dataSegment = dataSegments.get(dataidx);
			int memidx = (int) dataSegment.getIndex();
			if (memidx != 0)
				continue;

			Address dataStart = getProgramAddress(program, DATA_BASE + dataSegment.getFileOffset());
			try {
				/* Create a block for the data itself, for both passive and active segments */
				MemoryBlock block = program.getMemory().createInitializedBlock(".data" + dataidx, dataStart, fileBytes, dataSegment.getFileOffset(), dataSegment.getSize(), false);
				block.setRead(true);
				block.setWrite(false);
				block.setExecute(false);
			} catch (Exception e) {
				Msg.error(this, "Failed to create data segment " + dataidx + " at " + dataStart, e);
			}

			Long offset = dataSegment.getMemoryOffset();
			if (offset == null) {
				continue;
			}
			/* Copy active segments into memory when the offset is known */
			try {
				loadDataToMemory(program, module, dataidx, memidx, offset, monitor);
			} catch (Exception e) {
				Address memStart = getMemoryAddress(program, memidx, offset);
				Msg.error(this, "Failed to create data segment " + dataidx + " in memory " + memidx + " at " + memStart, e);
			}
		}
	}

	private void loadGlobals(Program program, FileBytes fileBytes, WasmModule module, TaskMonitor monitor) {
		List<WasmImportEntry> imports = module.getImports(WasmExternalKind.EXT_GLOBAL);
		List<WasmGlobalEntry> globals = module.getNonImportedGlobals();
		int numGlobals = imports.size() + globals.size();

		for (int globalidx = 0; globalidx < numGlobals; globalidx++) {
			WasmGlobalType globalType;
			byte[] initBytes;
			Long initRef;
			if (globalidx < imports.size()) {
				globalType = imports.get(globalidx).getGlobalType();
				initBytes = null;
				initRef = null;
			} else {
				WasmGlobalEntry entry = globals.get(globalidx - imports.size());
				globalType = entry.getGlobalType();
				initBytes = entry.asBytes(module);
				initRef = entry.asReference(module);
			}

			Address dataStart = getGlobalAddress(program, globalidx);
			try {
				MemoryBlock block;
				DataType dataType = globalType.getType().asDataType();
				if (initBytes == null) {
					block = program.getMemory().createUninitializedBlock(".global" + globalidx, dataStart, dataType.getLength(), false);
				} else {
					block = program.getMemory().createInitializedBlock(".global" + globalidx, dataStart, dataType.getLength(), (byte) 0xff, monitor, false);
					program.getMemory().setBytes(dataStart, initBytes);
				}
				block.setRead(true);
				block.setWrite((globalType.getMutability() != 0) ? true : false);
				block.setExecute(false);
				createData(program, program.getListing(), dataStart, dataType);
				program.getSymbolTable().createLabel(dataStart, "global" + globalidx, SourceType.IMPORTED);
			} catch (Exception e) {
				Msg.error(this, "Failed to create global " + globalidx + " at " + dataStart, e);
			}

			if (initRef != null) {
				Address refAddr = getProgramAddress(program, initRef);
				program.getReferenceManager().removeAllReferencesFrom(dataStart);
				program.getReferenceManager().addMemoryReference(dataStart, refAddr, RefType.DATA, SourceType.IMPORTED, 0);
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

		loadFunctions(program, fileBytes, module, monitor);
		loadTables(program, fileBytes, module, monitor);
		loadMemories(program, fileBytes, module, monitor);
		loadGlobals(program, fileBytes, module, monitor);
	}
}