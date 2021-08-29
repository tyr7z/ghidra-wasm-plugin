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
import wasm.format.WasmEnums.WasmExternalKind;
import wasm.format.WasmModule;
import wasm.format.sections.WasmCodeSection;
import wasm.format.sections.WasmFunctionSection;
import wasm.format.sections.WasmImportSection;
import wasm.format.sections.WasmTypeSection;
import wasm.format.sections.structures.WasmFuncType;
import wasm.format.sections.structures.WasmFunctionBody;
import wasm.format.sections.structures.WasmImportEntry;

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
		return module.getTypeSection().getType(typeidx);
	}

	public ValType getGlobalType(int globalidx) {
		return module.getGlobalSection().getEntries().get(globalidx).getType();
	}

	public ValType getTableType(int tableidx) {
		return module.getTableSection().getTables().get(tableidx).getElementType();
	}

	private static List<WasmFuncSignature> getFunctions(Program program, WasmModule module) {
		List<WasmFuncSignature> functions = new ArrayList<>();
		WasmImportSection importSection = module.getImportSection();
		WasmTypeSection typeSection = module.getTypeSection();
		if (importSection != null) {
			List<WasmImportEntry> imports = importSection.getEntries();
			int funcIdx = 0;
			for (WasmImportEntry entry : imports) {
				if (entry.getKind() != WasmExternalKind.EXT_FUNCTION)
					continue;
				int typeIdx = entry.getFunctionType();
				WasmFuncType funcType = typeSection.getType(typeIdx);
				Address addr = WasmLoader.getImportAddress(program, funcIdx);

				functions.add(new WasmFuncSignature(funcType.getParamTypes(), funcType.getReturnTypes(), entry.getName(), addr));
				funcIdx++;
			}
		}

		WasmFunctionSection functionSection = module.getFunctionSection();
		WasmCodeSection codeSection = module.getCodeSection();
		if (functionSection != null && codeSection != null) {
			List<WasmFunctionBody> methods = codeSection.getFunctions();
			for (int i = 0; i < methods.size(); ++i) {
				int typeidx = functionSection.getTypeIdx(i);
				WasmFuncType funcType = typeSection.getType(typeidx);
				WasmFunctionBody method = methods.get(i);

				Address startAddress = WasmLoader.getMethodAddress(program, method.getOffset());
				Address endAddress = WasmLoader.getMethodAddress(program, method.getOffset() + method.getInstructions().length);

				String name = null;
				Symbol[] labels = program.getSymbolTable().getSymbols(startAddress);
				if (labels.length > 0) {
					name = labels[0].getName();
				}

				byte[] params = funcType.getParamTypes();
				byte[] returns = funcType.getReturnTypes();
				byte[] nonparam_locals = method.getLocals();
				byte[] locals = new byte[params.length + nonparam_locals.length];

				System.arraycopy(params, 0, locals, 0, params.length);
				System.arraycopy(nonparam_locals, 0, locals, params.length, nonparam_locals.length);
				functions.add(new WasmFuncSignature(params, returns, name, startAddress, endAddress, locals));
			}
		}
		return functions;
	}
}
