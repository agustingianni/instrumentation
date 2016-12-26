#include <cstdio>
#include <cctype>
#include <fstream>
#include <iostream>
#include <algorithm>

#include "pin.H"
#include "ImageManager.h"
#include "json/json.h"
#include "HeapChunk.h"

using namespace std;

#ifdef __APPLE__
#include <unordered_set>
#include <unordered_map>
using namespace std::tr1;
#else
#include <unordered_set>
#include <unordered_map>
#endif

// By using the command line option '-w <module_name>' we can whitelist the modules.
static KNOB<string> KnobModuleWhitelist(KNOB_MODE_APPEND, "pintool", "w", "",
	"Add a module to the white list. If none is specified, everymodule is white-listed.");

static KNOB<string> KnobLogFile(KNOB_MODE_WRITEONCE, "pintool", "l", "log.json", "Name of the output file.");

// Create a TLS key.
static TLS_KEY tls_key;

// Return the thread's TLS.
static inline ThreadData *GetThreadLocalData(THREADID tid) {
	return static_cast<ThreadData *>(PIN_GetThreadData(tls_key, tid));
}

// Handle image white-listing.
static ImageManager image_manager;

// Maintain a vector of loaded images.
static std::vector<LoadedImage> loaded_images;
static PIN_LOCK lock_loaded_images;

// Thread safe time stamp manager.
static TimeStampManager timestamp_manager;

// Current set of heap chunks allocated by the application.
static set<HeapChunk> heap_chunks;
static PIN_LOCK lock_heap_chunks;

// Set of functions that used a heap chunk.
static set<InterestingFunction> interesting_functions;
static PIN_LOCK lock_interesting_functions;

static string base_name(const string &path) {
	string::size_type idx = path.rfind("/");
	string name = (idx == string::npos) ? path : path.substr(idx + 1);
	transform(name.begin(), name.end(), name.begin(), ::tolower);
	return name;
}

static VOID OnHeapFree(THREADID tid, ADDRINT address) {
	if (!address)
		return;

	PIN_GetLock(&lock_heap_chunks, 1);

	// Remove the freed chunk from the current chunk set.
	if (heap_chunks.erase(HeapChunk(address)) == 0) {
		cerr << "DEBUG: Chunk " << StringFromAddrint(address) << " missing from the chunk set." << endl;
	}

	PIN_ReleaseLock(&lock_heap_chunks);
}

static VOID OnHeapAllocationBefore(THREADID tid, ADDRINT size) {
	ThreadData *data = GetThreadLocalData(tid);
	data->m_alloc_size = size;
}

static VOID OnHeapAllocationAfter(THREADID tid, ADDRINT address) {
	if (!address)
		return;

	ThreadData *data = GetThreadLocalData(tid);

	PIN_GetLock(&lock_heap_chunks, 1);

	heap_chunks.insert(HeapChunk(address, data->m_alloc_size, timestamp_manager.get()));

	PIN_ReleaseLock(&lock_heap_chunks);
}

#ifdef _WIN32
static string demangle(const char* mangledName) {
	return string(mangledName);
}
#else
#include <cxxabi.h>
static string demangle(const char* mangledName) {
#ifdef __APPLE__
	mangledName++;
#endif
	int status;
	char* result = abi::__cxa_demangle(mangledName, nullptr, nullptr, &status);
	switch (status) {
	case -1:
		cerr << "Out of memory!" << endl;
		exit(1);
	case -2:
		return mangledName;
	case -3: // Should never happen, but just in case?
		return mangledName;
	}
	string name = result;
	free(result);
	return name;
}
#endif

// Image load event handler.
static VOID OnImageLoad(IMG img, VOID *v) {
	string img_name = base_name(IMG_Name(img));

	ADDRINT low = IMG_LowAddress(img);
	ADDRINT high = IMG_HighAddress(img);

	// Save the loaded image with its original name.
	PIN_GetLock(&lock_loaded_images, 1);
	loaded_images.push_back(LoadedImage(IMG_Name(img), low, high));
	PIN_ReleaseLock(&lock_loaded_images);

	// Only track the white listed modules
	if (image_manager.isWhiteListed(img_name))
		image_manager.addImage(img_name, low, high);

	if (IMG_Name(img).find("ld-linux") != string::npos)
		return;

	RTN rtn;
	const char *name;

	for (size_t i = 0; i < ARRAY_SIZE(malloc_names); i++) {
		name = malloc_names[i];
		rtn = RTN_FindByName(img, name);
		if (RTN_Valid(rtn)) {
			RTN_Open(rtn);
			printf("Instrumenting %-60s at 0x%.16llx on image %s\n", demangle(name).c_str(), RTN_Address(rtn),
				IMG_Name(img).c_str());

			// Pass the first argument of the allocation routine to the instrumentation function.
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) OnHeapAllocationBefore, IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);

			// Pass the return value of the allocation routine to the instrumentation function.
			RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR) OnHeapAllocationAfter, IARG_THREAD_ID,
				IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

			RTN_Close(rtn);
		}
	}

	for (size_t i = 0; i < ARRAY_SIZE(free_names); i++) {
		name = free_names[i];
		rtn = RTN_FindByName(img, name);
		if (RTN_Valid(rtn)) {
			RTN_Open(rtn);
			printf("Instrumenting %-60s at 0x%.16llx on image %s\n", demangle(name).c_str(), RTN_Address(rtn),
				IMG_Name(img).c_str());

			// Pass the first argument of the deallocation routine to the instrumentation function.
			RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) OnHeapFree, IARG_THREAD_ID, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);

			RTN_Close(rtn);
		}
	}
}

// Image unload event handler.
static VOID OnImageUnload(IMG img, VOID *v) {
	image_manager.removeImage(IMG_LowAddress(img));
}

// Function call event handler.
static VOID OnFunctionCall(THREADID tid, ADDRINT address, CONTEXT *context) {
	ADDRINT this_value;

#if _WIN32 || _WIN64
	this_value = PIN_GetContextReg(context, REG_GCX);

#elif __APPLE__ || (__x86_64__ && __linux)
	this_value = PIN_GetContextReg(context, REG_GDI);
#else
	PIN_SafeCopy(&this_value, (VOID *) PIN_GetContextReg(context, REG_STACK_PTR), sizeof(ADDRINT));
#endif

	PIN_GetLock(&lock_heap_chunks, 1);

	// Get the first chunk whose address is greater than 'this_value'.
	auto chunk = heap_chunks.upper_bound(HeapChunk(this_value));

	// Make sure the chunk exists.
	if (chunk == heap_chunks.end() || --chunk == heap_chunks.end()) {
		PIN_ReleaseLock(&lock_heap_chunks);
		return;
	}

	if (chunk->contains(this_value)) {
		PIN_GetLock(&lock_interesting_functions, 1);
		auto ret = interesting_functions.insert(InterestingFunction(address));
		ret.first->m_used_chunks.insert(*chunk);
		PIN_ReleaseLock(&lock_interesting_functions);
	}

	PIN_ReleaseLock(&lock_heap_chunks);
}

// Trace hit event handler.
static VOID OnTrace(TRACE trace, VOID *v) {
	BBL bbl = TRACE_BblHead(trace);

	// Check if the address is inside a white-listed image.
	if (!image_manager.isInterestingAddress(BBL_Address(bbl)))
		return;

	for (; BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
			// If the instruction is a function call, it could mark one of our heap chunks as interesting.
			if (INS_IsCall(ins)) {
				INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) OnFunctionCall, IARG_THREAD_ID,
					IARG_BRANCH_TARGET_ADDR, IARG_CONST_CONTEXT,
					IARG_END);
			}
		}
	}
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

static VOID log_interesting_functions(Json::Value &root) {
	Json::Value interesting_functions_json(Json::arrayValue);

	for (const auto &function : interesting_functions) {
		Json::Value chunks_json(Json::arrayValue);
		for (const auto &chunk : function.m_used_chunks) {
			Json::Value chunk_json(Json::objectValue);
			chunk_json["address"] = Json::Value((Json::UInt64) chunk.m_address);
			chunk_json["size"] = Json::Value((Json::UInt64) chunk.m_size);
			chunk_json["timestamp"] = Json::Value((Json::UInt64) chunk.m_timestamp);

			chunks_json.append(chunk_json);
		}

		Json::Value interesting_function_json(Json::objectValue);
		interesting_function_json["address"] = Json::Value((Json::UInt64) function.m_address);
		interesting_function_json["chunks"] = chunks_json;
		interesting_functions_json.append(interesting_function_json);
	}

	root["interesting_functions"] = interesting_functions_json;
}

// Program finish event handler.
static VOID OnFini(INT32 code, VOID *v) {
	Json::Value root(Json::objectValue);
	log_interesting_functions(root);
	log_loaded_images(root);

	cout << "Logging information to: " << KnobLogFile.ValueString() << endl;
	ofstream out(KnobLogFile.ValueString().c_str(), ofstream::out);
	out << root;
	out.close();
}

// Thread creation event handler.
static VOID OnThreadStart(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v) {
	PIN_SetThreadData(tls_key, new ThreadData, tid);
}

// Thread destruction event handler.
static VOID OnThreadFini(THREADID tid, const CONTEXT *ctxt, INT32 c, VOID *v) {
	ThreadData *data = GetThreadLocalData(tid);
	delete data;
}

int main(int argc, char *argv[]) {
	cout << "Recoverer tool by Agustin Gianni (agustingianni@gmail.com)" << endl;

	// Initialize symbol processing
	PIN_InitSymbols();

	// Initialize PIN.
	if (PIN_Init(argc, argv)) {
		cerr << "PIN_Init failed!" << endl;
		return -1;
	}

	// Handlers for thread creation and destruction.
	PIN_AddThreadStartFunction(OnThreadStart, 0);
	PIN_AddThreadFiniFunction(OnThreadFini, 0);

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

	PIN_InitLock(&lock_loaded_images);
	PIN_InitLock(&lock_interesting_functions);
	PIN_InitLock(&lock_heap_chunks);

	// Run the target program instrumented.
	PIN_StartProgram();

	return 0;
}
