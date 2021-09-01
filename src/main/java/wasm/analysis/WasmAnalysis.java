package wasm.analysis;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.plugin.core.analysis.AnalysisState;
import ghidra.app.plugin.core.analysis.AnalysisStateInfo;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import wasm.WasmLoader;
import wasm.format.WasmEnums.ValType;
import wasm.format.WasmModule;
import wasm.format.sections.structures.WasmFuncType;

public class WasmAnalysis implements AnalysisState {
	/**
	 * Return persistent <code>ClassFileAnalysisState</code> which corresponds to
	 * the specified program instance.
	 * 
	 * @param program
	 * @return <code>ClassFileAnalysisState</code> for specified program instance
	 */
	public static synchronized WasmAnalysis getState(Program program) {
		WasmAnalysis analysisState = AnalysisStateInfo.getAnalysisState(program, WasmAnalysis.class);
		if (analysisState == null) {
			analysisState = new WasmAnalysis(program);
			AnalysisStateInfo.putAnalysisState(program, analysisState);
		}
		return analysisState;
	}

	private WasmModule module = null;
	private List<WasmFuncSignature> functions = null;
	private Map<Function, WasmFunctionPreAnalysis> functionPreAnalyses = new HashMap<>();

	public WasmAnalysis(Program program) {
		Memory mem = program.getMemory();
		Address moduleStart = mem.getBlock(".module").getStart();
		ByteProvider memByteProvider = new MemoryByteProvider(mem, moduleStart);
		BinaryReader memBinaryReader = new BinaryReader(memByteProvider, true);
		WasmModule module = null;
		try {
			module = new WasmModule(memBinaryReader);
		} catch (IOException e) {
			Msg.error(this, "Failed to construct WasmModule", e);
		}

		this.module = module;
		this.functions = getFunctions(program, module);
	}

	public List<WasmFuncSignature> getFunctions() {
		return Collections.unmodifiableList(functions);
	}

	public WasmFuncSignature getFunction(int funcIdx) {
		return functions.get(funcIdx);
	}

	public WasmFunctionPreAnalysis getFunctionPreAnalysis(Function f) {
		return functionPreAnalyses.get(f);
	}

	public void setFunctionPreAnalysis(Function f, WasmFunctionPreAnalysis analysis) {
		functionPreAnalyses.put(f, analysis);
	}

	public WasmFuncType getType(int typeidx) {
		return module.getType(typeidx);
	}

	public ValType getGlobalType(int globalidx) {
		return module.getGlobalType(globalidx).getType();
	}

	public ValType getTableType(int tableidx) {
		return module.getTableType(tableidx).getElementType();
	}

	private static List<WasmFuncSignature> getFunctions(Program program, WasmModule module) {
		int numFunctions = module.getFunctionCount();
		List<WasmFuncSignature> functions = new ArrayList<>(numFunctions);
		for (int funcidx = 0; funcidx < numFunctions; funcidx++) {
			WasmFuncType funcType = module.getFunctionType(funcidx);
			Address startAddress = WasmLoader.getFunctionAddress(program, module, funcidx);
			Address endAddress = startAddress.add(WasmLoader.getFunctionSize(program, module, funcidx));

			String name = null;
			Symbol[] labels = program.getSymbolTable().getSymbols(startAddress);
			if (labels.length > 0) {
				name = labels[0].getName();
			}

			ValType[] params = funcType.getParamTypes();
			ValType[] returns = funcType.getReturnTypes();
			ValType[] nonparam_locals = module.getFunctionLocals(funcidx);
			if (nonparam_locals == null) {
				/* import */
				functions.add(new WasmFuncSignature(params, returns, name, startAddress));
			} else {
				ValType[] locals = new ValType[params.length + nonparam_locals.length];

				System.arraycopy(params, 0, locals, 0, params.length);
				System.arraycopy(nonparam_locals, 0, locals, params.length, nonparam_locals.length);
				functions.add(new WasmFuncSignature(params, returns, name, startAddress, endAddress, locals));
			}
		}
		return functions;
	}
}
