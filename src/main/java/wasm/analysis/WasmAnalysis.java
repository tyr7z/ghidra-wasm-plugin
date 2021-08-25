package wasm.analysis;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import wasm.WasmLoader;
import wasm.format.WasmFuncSignature;
import wasm.format.WasmModule;
import wasm.format.WasmEnums.WasmExternalKind;
import wasm.format.sections.WasmFunctionSection;
import wasm.format.sections.WasmImportSection;
import wasm.format.sections.WasmTypeSection;
import wasm.format.sections.structures.WasmFuncType;
import wasm.format.sections.structures.WasmImportEntry;

public class WasmAnalysis {
	private static HashMap<String, WasmAnalysis> states = new HashMap<>();
	public static WasmAnalysis getState(Program p) {
		String key = p.getExecutableSHA256();
		if(!states.containsKey(key)) {
			System.out.println("Creating new analysis state for "+p.getName());
			states.put(key, new WasmAnalysis(p));
		}
		return states.get(key);
	}
	
	private Program program;
	private HashMap<Function, WasmFunctionAnalysis> funcStates = new HashMap<>();
	private WasmFunctionAnalysis currMetaFunc = null;
	private WasmModule module = null;
	private ArrayList<WasmFuncSignature> functions = null;
	
	public WasmAnalysis(Program p) {
		this.program = p;
		
		Memory mem = program.getMemory();
		Address moduleStart = mem.getBlock(".module").getStart();
		ByteProvider memByteProvider = new MemoryByteProvider(mem, moduleStart);
		BinaryReader memBinaryReader = new BinaryReader(memByteProvider, true);
		WasmModule module = null;
		try {
			module = new WasmModule(memBinaryReader);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		this.module = module;
		
		this.findFunctionSignatures();
	}
	
	public Program getProgram() {
		return program;
	}
	
	public WasmFunctionAnalysis getFuncState(Function f) {
		if(!funcStates.containsKey(f)) {
			System.out.println("Creating new function analysis state for "+f.getName());
			funcStates.put(f, new WasmFunctionAnalysis(this, f));
		}
		return funcStates.get(f);
	}
	
	public void setModule(WasmModule module) {
		this.module = module;
	}
	
	public WasmFuncSignature getFuncSignature(int funcIdx) {
		return functions.get(funcIdx);
	}
	
	public WasmTypeSection getTypeSection() {
		return module.getTypeSection();
	}
	
	public void findFunctionSignatures() {
		functions = new ArrayList<>();
		WasmImportSection importSection = module.getImportSection();
		WasmTypeSection typeSection = module.getTypeSection();
		if(importSection != null) {
			List<WasmImportEntry> imports = importSection.getEntries();
			int funcIdx = 0;
			for(WasmImportEntry entry : imports) {
				if(entry.getKind() != WasmExternalKind.EXT_FUNCTION) continue;
				int typeIdx = entry.getFunctionType();
				WasmFuncType funcType = typeSection.getType(typeIdx);
				Address addr = WasmLoader.getImportAddress(program, funcIdx);
				
				functions.add(new WasmFuncSignature(funcType.getParamTypes(), funcType.getReturnTypes(), entry.getName(), addr));
				funcIdx++;
			}
		}
		
		WasmFunctionSection functionSection = module.getFunctionSection();
		if(functionSection != null) {
			FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
			int i = 0;
			//non-imported functions will show up first and in order since we are iterating by entry point
			for(Function func : funcIter) {
				if(i >= functionSection.getTypeCount()) break;
				int typeidx = functionSection.getTypeIdx(i);
				WasmFuncType funcType = typeSection.getType(typeidx);
				
				functions.add(new WasmFuncSignature(funcType.getParamTypes(), funcType.getReturnTypes(), null, func.getEntryPoint()));
				i++;
			}
		}
	}
	
	public boolean collectingMetas() {
		return currMetaFunc != null;
	}
	
	public void startCollectingMetas(WasmFunctionAnalysis f) {
		this.currMetaFunc = f;
	}
	
	public void stopCollectingMetas() {
		this.currMetaFunc = null;
	}
	
	public void performResolution() {
		for(HashMap.Entry<Function, WasmFunctionAnalysis> entry: funcStates.entrySet()) {
			entry.getValue().performResolution();
		}
	}
	
	public void collectMeta(MetaInstruction meta) {
		if(currMetaFunc == null) return;
		currMetaFunc.collectMeta(meta);
	}
}
