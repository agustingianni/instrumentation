#include <cstdio>
#include <fstream>
#include <iostream>
#include <algorithm>

#include "pin.H"
#include "ImageManager.h"

using namespace std;

#ifdef __APPLE__
#include <tr1/unordered_set>
#include <tr1/unordered_map>
using namespace std::tr1;
#else
#include <unordered_set>
#include <unordered_map>
#endif

// By using the command line option '-w <module_name>' we can whitelist the modules.
static KNOB<string> KnobModuleWhitelist(KNOB_MODE_APPEND, "pintool", "w", "",
	"Add a module to the white list. If none is specified, everymodule is white-listed.");

static KNOB<string> KnobLogFile(KNOB_MODE_WRITEONCE, "pintool", "l", "log.json", "Name of the output file.");

// Handle image white-listing.
static ImageManager image_manager;

// Build a dictionary with using the indirect branch PC as the key and a set of target addresses.
static PIN_LOCK resolved_lock;
static unordered_map<ADDRINT, unordered_set<ADDRINT> > indirect_branches;

// Build a dictionary using the vtable address as the key and a set of addresses where it is being used.
static PIN_LOCK vtables_lock;
static unordered_map<ADDRINT, unordered_set<ADDRINT> > vtables;

// Build a set of all the functions called by the program.
static PIN_LOCK functions_lock;
static unordered_map<ADDRINT, unordered_set<ADDRINT> > direct_branches;

// Build a set of all the insteresting instructions.
static PIN_LOCK interesting_ins_lock;
static unordered_set<ADDRINT> interesting_ins;

// Maintain a vector of loaded images.
static std::vector<LoadedImage> loaded_images;
static PIN_LOCK images_lock;

static string base_name(const string &path) {
	string::size_type idx = path.rfind("/");
	string name = (idx == string::npos) ? path : path.substr(idx + 1);
	transform(name.begin(), name.end(), name.begin(), ::tolower);
	return name;
}

// Image load event handler.
static VOID OnImageLoad(IMG img, VOID *v) {
	string img_name = base_name(IMG_Name(img));

	ADDRINT low = IMG_LowAddress(img);
	ADDRINT high = IMG_HighAddress(img);

	// Save the loaded image with its original name.
	PIN_GetLock(&images_lock, 1);
	loaded_images.push_back(LoadedImage(IMG_Name(img), low, high));
	PIN_ReleaseLock(&images_lock);

	// Only track the white listed modules
	if (image_manager.isWhiteListed(img_name))
		image_manager.addImage(img_name, low, high);
}

// Image unload event handler.
static VOID OnImageUnload(IMG img, VOID *v) {
	string img_name = base_name(IMG_Name(img));
	image_manager.removeImage(IMG_LowAddress(img));
}

// Indirect branch event handler.
static VOID OnIndirectBranch(ADDRINT branch_address, ADDRINT branch_target) {
	PIN_GetLock(&resolved_lock, 1);
	indirect_branches[branch_address].insert(branch_target);
	PIN_ReleaseLock(&resolved_lock);
}

// Indirect call event handler.
static VOID OnIndirectCall(ADDRINT branch_address, ADDRINT vtable_base, CONTEXT *context) {
	ADDRINT obj_address, mem_value;

	// Search for the register that contains the pointer to the this pointer. Most likely ECX / RCX.
	for (REG reg = REG_GR_BASE; reg != REG_GR_LAST; reg = REG(reg + 1)) {
		obj_address = PIN_GetContextReg(context, reg);

		// If obj_address is really the object, then on its first DWORD it should have the VTABLE base.
		if (PIN_SafeCopy(&mem_value, (VOID *) obj_address, sizeof(ADDRINT)) != sizeof(ADDRINT))
			continue;

		// If they differ, search for the next register
		if (mem_value != vtable_base)
			continue;

		PIN_GetLock(&vtables_lock, 2);
		vtables[vtable_base].insert(branch_address);
		PIN_ReleaseLock(&vtables_lock);

		return;
	}
}

// Indirect call event handler.
static VOID OnDirectCall(ADDRINT branch_address, ADDRINT branch_target) {
	PIN_GetLock(&functions_lock, 3);
	direct_branches[branch_target].insert(branch_address);
	PIN_ReleaseLock(&functions_lock);
}

static VOID OnInterestingInstruction(ADDRINT instruction_addr) {
	PIN_GetLock(&interesting_ins_lock, 3);
	interesting_ins.insert(instruction_addr);
	PIN_ReleaseLock(&interesting_ins_lock);
}

static BOOL INS_IsSignExtend(const INS &ins) {
	switch (INS_Opcode(ins)) {
	case XED_ICLASS_MOVSX:
	case XED_ICLASS_MOVSXD:
		return true;
	default:
		return false;
	}
}

static BOOL INS_HasRepPrefix(const INS &ins) {
	switch (INS_Opcode(ins)) {
	case XED_ICLASS_MOVSB:
	case XED_ICLASS_MOVSW:
	case XED_ICLASS_MOVSD:
	case XED_ICLASS_MOVSQ:
	case XED_ICLASS_STOSB:
	case XED_ICLASS_STOSW:
	case XED_ICLASS_STOSD:
	case XED_ICLASS_STOSQ:
	case XED_ICLASS_LODSB:
	case XED_ICLASS_LODSW:
	case XED_ICLASS_LODSD:
	case XED_ICLASS_LODSQ:
	case XED_ICLASS_SCASB:
	case XED_ICLASS_SCASW:
	case XED_ICLASS_SCASD:
	case XED_ICLASS_SCASQ:
	case XED_ICLASS_CMPSB:
	case XED_ICLASS_CMPSW:
	case XED_ICLASS_CMPSD:
	case XED_ICLASS_CMPSQ:
		return true;
	default:
		return false;
	}
}

// Trace hit event handler.
static VOID OnTrace(TRACE trace, VOID *v) {
	BBL bbl = TRACE_BblHead(trace);

	// Check if the address is inside a white-listed image.
	if (!image_manager.isInterestingAddress(BBL_Address(bbl)))
		return;

	for (; BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
			if (INS_IsIndirectBranchOrCall(ins) && !INS_IsRet(ins)) {
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) OnIndirectBranch, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR,
				IARG_END);

				if (INS_Opcode(ins) == XED_ICLASS_CALL_NEAR) {
					// Effective address = Displacement + BaseReg + IndexReg * Scale
					REG base_reg = INS_OperandMemoryBaseReg(ins, 0);
					if (base_reg != REG_INVALID()) {
						INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) OnIndirectCall, IARG_INST_PTR, IARG_REG_VALUE,
							base_reg, IARG_CONST_CONTEXT,
							IARG_END);
					}
				}
			} else if (INS_IsDirectCall(ins)) {
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) OnDirectCall, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR,
				IARG_END);
			} else if (INS_IsSignExtend(ins) || INS_HasRepPrefix(ins)) {
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) OnInterestingInstruction, IARG_INST_PTR,
				IARG_END);
			}
		}
	}
}

#include "json/json.h"

static VOID log_indirect_branches(Json::Value &root) {
	// Save all the indirect branches.
	Json::Value indirect_branches_json(Json::arrayValue);
	for (const auto &kv : indirect_branches) {
		Json::Value entry(Json::objectValue);
		Json::Value entries(Json::arrayValue);

		for (const auto &el : kv.second) {
			entries.append(Json::Value((Json::UInt64) el));
		}

		// Build the entry.
		entry["from"] = Json::Value((Json::UInt64) kv.first);
		entry["to"] = entries;

		// Append the entry to the array of entries.
		indirect_branches_json.append(entry);
	}

	root["indirect_branches"] = indirect_branches_json;
}

static VOID log_vtables(Json::Value &root) {
	Json::Value vtables_json(Json::arrayValue);
	for (const auto &kv : vtables) {
		Json::Value entry(Json::objectValue);
		Json::Value entries(Json::arrayValue);

		for (const auto &el : kv.second) {
			entries.append(Json::Value((Json::UInt64) el));
		}

		// Build the entry.
		entry["vtable"] = Json::Value((Json::UInt64) kv.first);
		entry["references"] = entries;

		vtables_json.append(entry);
	}

	root["vtables"] = vtables_json;
}

static VOID log_direct_branches(Json::Value &root) {
	Json::Value direct_branches_json(Json::arrayValue);
	for (const auto &kv : direct_branches) {
		Json::Value entry(Json::objectValue);
		Json::Value entries(Json::arrayValue);

		for (const auto &el : kv.second) {
			entries.append(Json::Value((Json::UInt64) el));
		}

		// Build the entry.
		entry["function"] = Json::Value((Json::UInt64) kv.first);
		entry["references"] = entries;

		direct_branches_json.append(entry);
	}

	root["direct_branches"] = direct_branches_json;
}

static VOID log_loaded_images(Json::Value &root) {
	Json::Value loaded_images_json(Json::arrayValue);
	for (const auto &el : loaded_images) {
		Json::Value entry(Json::objectValue);
		entry["name"] = Json::Value(el.name_);
		entry["lo_addr"] = Json::Value((Json::UInt64) el.low_);
		entry["hi_addr"] = Json::Value((Json::UInt64) el.high_);
		loaded_images_json.append(entry);
	}

	root["loaded_images"] = loaded_images_json;
}

static VOID log_interesting_instructions(Json::Value &root) {
	Json::Value interesting_instructions_json(Json::arrayValue);
	for (const auto &el : interesting_ins) {
		Json::Value entry(Json::objectValue);
		entry["address"] = Json::Value((Json::UInt64) el);
		interesting_instructions_json.append(entry);
	}

	root["interesting_instructions"] = interesting_instructions_json;
}

// Program finish event handler.
static VOID OnFini(INT32 code, VOID *v) {
	Json::Value root(Json::objectValue);
	log_indirect_branches(root);
	log_vtables(root);
	log_direct_branches(root);
	log_loaded_images(root);
	log_interesting_instructions(root);

	cout << "Logging information to: " << KnobLogFile.ValueString() << endl;
	ofstream out(KnobLogFile.ValueString().c_str(), ofstream::out);
	out << root;
	out.close();
}

int main(int argc, char *argv[]) {
	cout << "Resolver tool by Agustin Gianni (Preto Inc.)" << endl;

	// Initialize symbol processing
	PIN_InitSymbols();

	// Initialize PIN.
	if (PIN_Init(argc, argv)) {
		cerr << "PIN_Init failed!" << endl;
		return -1;
	}

	// Image load/unload instrumentation.
	IMG_AddInstrumentFunction(OnImageLoad, 0);
	IMG_AddUnloadFunction(OnImageUnload, 0);

	// Trace level instrumentation.
	TRACE_AddInstrumentFunction(OnTrace, 0);

	// Instrument program exit.
	PIN_AddFiniFunction(OnFini, 0);

	if (!KnobModuleWhitelist.NumberOfValues()) {
		cout << "White-listed images not specified, instrumenting every module by default." << endl;
	}

	for (unsigned i = 0; i < KnobModuleWhitelist.NumberOfValues(); ++i) {
		cout << "White-listing image: " << KnobModuleWhitelist.Value(i) << endl;
		image_manager.addWhiteListedImage(KnobModuleWhitelist.Value(i));
	}

	PIN_InitLock(&vtables_lock);
	PIN_InitLock(&images_lock);
	PIN_InitLock(&resolved_lock);

	// Run the target program instrumented.
	PIN_StartProgram();

	return 0;
}
