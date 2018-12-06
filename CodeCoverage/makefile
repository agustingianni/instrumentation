CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
include $(CONFIG_ROOT)/makefile.config

TOOL_ROOTS := CodeCoverage
TOOL_CXXFLAGS += -std=c++11 -Wno-format -I ../common

# Newer GCC's need this flag to compile.
ifeq ($(TARGET_OS),linux)
    TOOL_CXXFLAGS += -faligned-new
endif

$(OBJDIR)CodeCoverage$(PINTOOL_SUFFIX): $(OBJDIR)CodeCoverage$(OBJ_SUFFIX) ../common/$(OBJDIR)ImageManager$(OBJ_SUFFIX)
	$(LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $^ $(TOOL_LPATHS) $(TOOL_LIBS)

include $(TOOLS_ROOT)/Config/makefile.default.rules