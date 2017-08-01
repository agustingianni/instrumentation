#include <iostream>
#include <string>
#include <vector>
#include <utility>
#include <iterator>
#include <algorithm>
#include <cstdio>
#include <cstdarg>
#include <cstdlib>

#include "pin.H"
#include "DiskPool.h"

static KNOB<std::string> KnobLogFile(KNOB_MODE_WRITEONCE, "pintool", "l", "trace.log",
    "Name of the output file. If none is specified, trace.log is used.");

// Return the file/directory name of a path.
static string base_name(const std::string& path)
{
#if defined(TARGET_WINDOWS)
#define PATH_SEPARATOR "\\"
#else
#define PATH_SEPARATOR "/"
#endif
    string::size_type idx = path.rfind(PATH_SEPARATOR);
    string name = (idx == string::npos) ? path : path.substr(idx + 1);
    return name;
}

enum class EventType : uint8_t {
    BASIC_BLOCK_EVENT,
    IMAGE_EVENT
};

struct BaseEvent {
    BaseEvent(EventType type)
        : m_type(type)
    {
    }

    EventType m_type;
};

struct BasicBlockEvent : public BaseEvent {
    BasicBlockEvent(uint64_t address, uint32_t size)
        : BaseEvent(EventType::BASIC_BLOCK_EVENT)
        , m_address(address)
        , m_size(size)
    {
    }

    static size_t size()
    {
        return sizeof(BasicBlockEvent);
    }

    uint64_t m_address;
    uint32_t m_size;
};

struct String {
    String(const std::string& str)
        : m_size(str.size())
    {
        memcpy(m_data, str.c_str(), str.size());
    }

    uint16_t m_size;
    char m_data[0];
};

struct ImageEvent : public BaseEvent {
    ImageEvent(const std::string& name, uint64_t address_lo, uint64_t address_hi)
        : BaseEvent(EventType::IMAGE_EVENT)
        , m_address_hi(address_hi)
        , m_address_lo(address_lo)
        , m_name(name)
    {
    }

    static size_t size(const std::string& name)
    {
        return sizeof(ImageEvent) + sizeof(String) + name.size();
    }

    uint64_t m_address_hi;
    uint64_t m_address_lo;
    String m_name;
};

class IOThread;
class ToolContext {
public:
    ToolContext()
    {
    }

    DiskPoolRaw* m_pool;
    IOThread* m_io_thread;
};

#include <boost/memory_order.hpp>
#include <boost/atomic/atomic.hpp>

class IOThread {
public:
    IOThread(DiskPoolRaw* pool)
        : m_pool(pool)
    {
    }

    void start()
    {
        printf("Starting IO thread.\n");
        if (PIN_SpawnInternalThread(IOThread::dispatch, this, 0, &m_tid) == INVALID_THREADID) {
            cerr << "Error creating I/O thread!" << endl;
            abort();
        }
    }

    void stop()
    {
        printf("Stopping IO thread.\n");
        m_stop.store(1);

        printf("Waiting I/O thread to finish.\n");
        PIN_WaitForThreadTermination(m_tid, PIN_INFINITE_TIMEOUT, nullptr);
    }

private:
    static void dispatch(VOID* arg)
    {
        IOThread* self = reinterpret_cast<IOThread*>(arg);
        self->run();
    }

    void run()
    {
        while (!m_stop.load(boost::memory_order::memory_order_acquire)) {
            sleep(1);
            m_pool->flush();
        }
    }

    PIN_THREAD_UID m_tid;
    boost::atomic<int> m_stop{ 0 };
    DiskPoolRaw* m_pool;
};

static ToolContext* g_context = nullptr;

// Image load event handler.
static VOID OnImageLoad(IMG img, VOID* v)
{
    auto full_name = IMG_Name(img);
    string img_name = base_name(full_name);
    ADDRINT low = IMG_LowAddress(img);
    ADDRINT high = IMG_HighAddress(img);
    printf("Loaded image: 0x%.16lx:0x%.16lx -> %s\n", low, high, img_name.c_str());

    auto memory = reinterpret_cast<ImageEvent*>(g_context->m_pool->alloc(ImageEvent::size(full_name)));
    new (memory) ImageEvent(full_name, low, high);
}

// Basic block hit event handler.
static VOID OnBasicBlockHit(ADDRINT addr, UINT32 size)
{
    auto memory = reinterpret_cast<BasicBlockEvent*>(g_context->m_pool->alloc(BasicBlockEvent::size()));
    new (memory) BasicBlockEvent(addr, size);
}

// Trace hit event handler.
static VOID OnTrace(TRACE trace, VOID* v)
{
    return;

    BBL bbl = TRACE_BblHead(trace);
    ADDRINT addr = BBL_Address(bbl);

    // For each basic block in the trace.
    for (; BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        addr = BBL_Address(bbl);
        BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR)OnBasicBlockHit,
            IARG_ADDRINT, addr,
            IARG_UINT32, BBL_Size(bbl),
            IARG_END);
    }
}

// Program start event handler.
static VOID OnStart(VOID* v)
{
    printf("Application is starting.\n");
    g_context->m_io_thread->start();
}

// Program finish event handler.
static VOID OnFini(INT32 code, VOID* v)
{
    printf("Application is finishing.\n");
    g_context->m_io_thread->stop();
}

int main(int argc, char* argv[])
{
    cout << "CodeCoverage tool by Agustin Gianni (agustingianni@gmail.com)" << endl;

    // Initialize symbol processing
    PIN_InitSymbols();

    // Initialize PIN.
    if (PIN_Init(argc, argv)) {
        cerr << "Error initializing PIN, PIN_Init failed!" << endl;
        return -1;
    }

    // Initialize the tool context.
    g_context = new ToolContext();
    g_context->m_pool = new DiskPoolRaw(KnobLogFile.ValueString().c_str(), GB(1));
    g_context->m_io_thread = new IOThread(g_context->m_pool);

    // Create a trace file.
    cout << "Logging code coverage information to: " << KnobLogFile.ValueString() << endl;

    // Handlers for image loading.
    IMG_AddInstrumentFunction(OnImageLoad, nullptr);

    // Handlers for instrumentation events.
    TRACE_AddInstrumentFunction(OnTrace, nullptr);

    // Handler for program start/exit.
    PIN_AddFiniFunction(OnFini, nullptr);
    PIN_AddApplicationStartFunction(OnStart, nullptr);

    PIN_StartProgram();
    return 0;
}
