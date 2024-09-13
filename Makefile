# tool macros
CC ?= gcc
CXX ?= # FILL: the compiler
PYFLAGS = $(shell python3-config --includes) $(shell python3-config --ldflags --embed) 
CFLAGS := -lpcap $(PYFLAGS)
CXXFLAGS := # FILL: compile flags
DBGFLAGS := -g
COBJFLAGS := $(CFLAGS) -c

# path macros
BIN_PATH := bin
OBJ_PATH := obj
SRC_PATH := src
DBG_PATH := debug
TEST_PATH := test
PCAP_PATH := pcap

# compile macros
TARGET_NAME := tsdn
TARGET := $(BIN_PATH)/$(TARGET_NAME)
TARGET_DEBUG := $(DBG_PATH)/$(TARGET_NAME)
TARGET_TEST := $(BIN_PATH)/test

# src files & obj files
HEADERS := $(wildcard $(SRC_PATH)/*.h)
SRC := $(foreach x, $(SRC_PATH), $(wildcard $(addprefix $(x)/*,.c*)))
OBJ := $(addprefix $(OBJ_PATH)/, $(addsuffix .o, $(notdir $(basename $(SRC)))))
OBJ_DEBUG := $(addprefix $(DBG_PATH)/, $(addsuffix .o, $(notdir $(basename $(SRC)))))

# clean files list
DISTCLEAN_LIST := $(OBJ) \
                  $(OBJ_DEBUG)
CLEAN_LIST := $(TARGET) \
			  $(TARGET_DEBUG) \
			  $(DISTCLEAN_LIST)

# default rule
default: makedir all

# non-phony targets
$(TARGET): $(OBJ)
	$(CC) -o $@ $(OBJ) $(CFLAGS)

$(OBJ_PATH)/%.o: $(SRC_PATH)/%.c*
	$(CC) $(COBJFLAGS) -o $@ $<

$(DBG_PATH)/%.o: $(SRC_PATH)/%.c*
	$(CC) $(COBJFLAGS) $(DBGFLAGS) -o $@ $<

$(TARGET_DEBUG): $(OBJ_DEBUG)
	$(CC) -o $@ $(DBGFLAGS) $(OBJ_DEBUG) $(CFLAGS)

$(TARGET_TEST): $(TEST_PATH)/test.c
	$(CC) -o $@ $< $(CFLAGS)


# phony rules
.PHONY: makedir
makedir:
	@mkdir -p $(BIN_PATH) $(OBJ_PATH) $(DBG_PATH) $(TEST_PATH)

.PHONY: all
all: $(TARGET)

.PHONY: debug
debug: $(TARGET_DEBUG)

.PHONY: test
test: $(TARGET_TEST)

.PHONY: clean
clean:
	@echo CLEAN $(CLEAN_LIST)
	@rm -f $(CLEAN_LIST)
	@rm -f $(BIN_PATH)/*
	@rm -f $(OBJ_PATH)/*
	@rm -f $(DBG_PATH)/*
	@rm -f $(PCAP_PATH)/*


.PHONY: p4clean
p4clean:
	@sudo rm -rf p4/log/*

.PHONY: distclean
distclean:
	@echo CLEAN $(DISTCLEAN_LIST)
	@rm -f $(DISTCLEAN_LIST)

.PHONY: echo
echo:
	@echo $(PYFLAGS)