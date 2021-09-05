package wasm.analysis;

import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class WasmPreAnalyzer extends AbstractAnalyzer {
	private final static String NAME = "Wasm Pre-Analyzer";
	private final static String DESCRIPTION = "Analyze Wasm code before disassembly to resolve operand sizes and jump offsets";

	private final static String OPTION_NAME_CSTACK_GLOBAL = "C Stack Pointer";
	private static final String OPTION_DESCRIPTION_CSTACK_GLOBAL = "Index of the global variable being used as the C stack pointer. Set to -1 to disable C stack inference.";
	/* Default to global0, which is what Emscripten appears to do */
	private final static int OPTION_DEFAULT_CSTACK_GLOBAL = 0;
	private int cStackGlobal = OPTION_DEFAULT_CSTACK_GLOBAL;

	public WasmPreAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		// run immediately before initial disassembly
		setPriority(AnalysisPriority.BLOCK_ANALYSIS.before());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(Processor.findOrPossiblyCreateProcessor("Webassembly"));
	}

	@Override
	public void registerOptions(Options options, Program program) {
		HelpLocation helpLocation = new HelpLocation("AutoAnalysisPlugin", "Auto_Analysis_Option_Instructions");

		options.registerOption(OPTION_NAME_CSTACK_GLOBAL, cStackGlobal, helpLocation,
				OPTION_DESCRIPTION_CSTACK_GLOBAL);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		cStackGlobal = options.getInt(OPTION_NAME_CSTACK_GLOBAL, cStackGlobal);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
		WasmAnalysis state = WasmAnalysis.getState(program);
		List<WasmFuncSignature> functions = state.getFunctions();
		monitor.initialize(functions.size());

		Disassembler disassembler = Disassembler.getDisassembler(program, monitor, new DisassemblerMessageListener() {
			@Override
			public void disassembleMessageReported(String msg) {
				if (monitor != null) {
					monitor.setMessage(msg);
				}
			}
		});
		disassembler.setRepeatPatternLimit(-1);

		/*
		 * TODO: Support reanalyzing changed functions, to handle patches and
		 * significant function changes.
		 */
		for (Function function : program.getListing().getFunctions(set, true)) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress(1);

			WasmFuncSignature func = state.getFunctionByAddress(function.getEntryPoint());
			if (func.isImport()) {
				continue;
			}
			WasmFunctionPreAnalysis funcAnalysis = state.getFunctionPreAnalysis(function);
			funcAnalysis.applyContext(program, cStackGlobal);
			AddressSet funcSet = new AddressSet(func.getStartAddr(), func.getEndAddr());
			disassembler.disassemble(funcSet, funcSet, false);
		}
		return true;
	}
}
