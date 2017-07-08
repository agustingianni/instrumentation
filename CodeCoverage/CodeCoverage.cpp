#include <iostream>
#include <set>
#include <vector>
#include <cstdio>

#include "pin.H"
#include "ImageManager.h"

#if defined(TARGET_WINDOWS) || defined(TARGET_MAC)
#include <unordered_set>
using namespace std::tr1;
#else
#include <unordered_set>
#endif

using namespace std;

// Save each hit to a hash table.
typedef unordered_set<ADDRINT> blocks_t;

// By using the command line option '-w <module_name>' we can whitelist the modules.
static KNOB<string> KnobModuleWhitelist(KNOB_MODE_APPEND, "pintool", "w", "",
    "Add a module to the white list. If none is specified, everymodule is white-listed. Example: libTIFF.dylib");

static KNOB<string> KnobTraceName(KNOB_MODE_APPEND, "pintool", "n", "",
    "Define the name of the trace.");

static KNOB<string> KnobLogFile(KNOB_MODE_WRITEONCE, "pintool", "l", "trace.log", "Name of the output file.");

// Log file and its lock.
static FILE* log_fd;
static PIN_LOCK log_lock;

// Handle image white-listing.
static ImageManager image_manager;

static bool tracing_enabled = true;

// Each thread will have a set of basic block hits and a log file.
struct ThreadData {
    blocks_t m_block_hit;
};

static TLS_KEY tls_key;

// Maintain a vector of loaded images.
static std::vector<LoadedImage> loaded_images;
static PIN_LOCK images_lock;

// Return the thread's TLS.
static inline ThreadData* GetThreadLocalData(THREADID tid)
{
    return static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
}

// Track the created threads because sometimes the app dies before shutting down the threads.
static set<THREADID> seen_threads;

// We dump the collected information per thread when the thread dies.
static VOID DumpThreadInformation(THREADID tid, ThreadData* data)
{
    PIN_GetLock(&log_lock, 1);

    for (ADDRINT hit : data->m_block_hit) {
        fprintf(log_fd, "H;0x%.16lx\n", hit);
    }

    PIN_ReleaseLock(&log_lock);
}

// Thread creation event handler.
static VOID OnThreadStart(THREADID tid, CONTEXT* ctxt, INT32 flags, VOID* v)
{
    PIN_SetThreadData(tls_key, new ThreadData, tid);
    seen_threads.insert(tid);
}

// Thread destruction event handler.
static VOID OnThreadFini(THREADID tid, const CONTEXT* ctxt, INT32 c, VOID* v)
{
    ThreadData* data = GetThreadLocalData(tid);
    DumpThreadInformation(tid, data);

    // Free the resources.
    data->m_block_hit.clear();
    delete data;

    // Remove the thread as its TID may be reused.
    seen_threads.erase(tid);
}

static string base_name(const string& path)
{
    string::size_type idx = path.rfind("/");
    string name = (idx == string::npos) ? path : path.substr(idx + 1);
    return name;
}

// Image load event handler.
static VOID OnImageLoad(IMG img, VOID* v)
{
    string img_name = base_name(IMG_Name(img));

    ADDRINT low = IMG_LowAddress(img);
    ADDRINT high = IMG_HighAddress(img);

    printf("Loaded image: 0x%.16lx:0x%.16lx -> %s\n", low, high, img_name.c_str());

    // Save the loaded image with its original name.
    PIN_GetLock(&images_lock, 1);
    loaded_images.push_back(LoadedImage(IMG_Name(img), low, high));
    PIN_ReleaseLock(&images_lock);

    // Only track the white listed modules
    if (image_manager.isWhiteListed(img_name)) {
        image_manager.addImage(img_name, low, high);
        tracing_enabled = true;
    }
}

// Image unload event handler.
static VOID OnImageUnload(IMG img, VOID* v)
{
    string img_name = base_name(IMG_Name(img));
    image_manager.removeImage(IMG_LowAddress(img));
}

// Basic block hit event handler.
static VOID OnBasicBlockHit(THREADID tid, ADDRINT a)
{
    ThreadData* data = GetThreadLocalData(tid);
    data->m_block_hit.insert(a);
}

// Trace hit event handler.
static VOID OnTrace(TRACE trace, VOID* v)
{
    BBL bbl = TRACE_BblHead(trace);
    ADDRINT addr = BBL_Address(bbl);

    // Check if the address is inside a white-listed image.
    if (!tracing_enabled || !image_manager.isInterestingAddress(addr))
        return;

    // For each basic block in the trace.
    for (; BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        addr = BBL_Address(bbl);

        BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR)OnBasicBlockHit, IARG_THREAD_ID, IARG_ADDRINT, addr,
            IARG_END);
    }
}

// Program finish event handler.
static VOID OnFini(INT32 code, VOID* v)
{
    // For each non terminated thread, dump its TLS info
    for (THREADID i : seen_threads) {
        ThreadData* data = GetThreadLocalData(i);
        DumpThreadInformation(i, data);
        data->m_block_hit.clear();
        delete data;
    }

    PIN_GetLock(&log_lock, 1);

    // Log all the loaded images.
    for (const LoadedImage& image : loaded_images) {
        fprintf(log_fd, "L;%s;0x%.16lx;0x%.16lx\n", image.name_.c_str(), image.low_, image.high_);
    }

    fclose(log_fd);

    log_fd = nullptr;

    PIN_ReleaseLock(&log_lock);
}

int main(int argc, char* argv[])
{
    cout << "CodeCoverage tool by Agustin Gianni (agustingianni@gmail.com)" << endl;

    // Initialize symbol processing
    PIN_InitSymbols();

    // Initialize PIN.
    if (PIN_Init(argc, argv)) {
        cerr << "PIN_Init failed!" << endl;
        return -1;
    }

    // Initialize the lock for the image list.
    PIN_InitLock(&images_lock);

    // Initialize the lock for the log file.
    PIN_InitLock(&log_lock);

    if (!KnobModuleWhitelist.NumberOfValues()) {
        cout << "White-listed images not specified, instrumenting every module by default." << endl;
    }

    for (unsigned i = 0; i < KnobModuleWhitelist.NumberOfValues(); ++i) {
        cout << "White-listing image: " << KnobModuleWhitelist.Value(i) << endl;
        image_manager.addWhiteListedImage(KnobModuleWhitelist.Value(i));

        // We will only enable tracing when any of the whitelisted images gets loaded.
        tracing_enabled = false;
    }

    // Create our TLS key.
    tls_key = PIN_CreateThreadDataKey(nullptr);

    // Open the log file.
    cout << "Logging code coverage information to: " << KnobLogFile.ValueString() << endl;
    log_fd = fopen(KnobLogFile.ValueString().c_str(), "w+");
    if (!log_fd) {
        cerr << "Could not open the log file" << endl;
    }

    // Handlers for thread creation and destruction.
    PIN_AddThreadStartFunction(OnThreadStart, 0);
    PIN_AddThreadFiniFunction(OnThreadFini, 0);

    IMG_AddInstrumentFunction(OnImageLoad, 0);
    IMG_AddUnloadFunction(OnImageUnload, 0);
    TRACE_AddInstrumentFunction(OnTrace, 0);
    PIN_AddFiniFunction(OnFini, 0);

    PIN_StartProgram();

    return 0;
}
