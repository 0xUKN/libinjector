CC=g++
CCFLAGS=-c -fPIC
LDFLAGS=-ldl -s
LDFLAGS_SO=-shared
BUILD_DIR=build
SOURCE_DIR=src
BIN_DIR=bin
EXEC=library_injector
LIBRARY=libinjector.so
SOURCE_EXT=cpp
SOURCES=$(shell find $(SOURCE_DIR) -type f -name *.$(SOURCE_EXT))
OBJECTS=$(patsubst $(SOURCE_DIR)/%,$(BUILD_DIR)/%,$(SOURCES:.$(SOURCE_EXT)=.o))
OBJECTS_SO=$(filter-out $(EXEC).$(SOURCE_EXT),$(OBJECTS))


$(EXEC): $(OBJECTS)
	@mkdir -p $(BIN_DIR)
	$(CC) $^ -o $(BIN_DIR)/$@ $(LDFLAGS)

$(LIBRARY): $(OBJECTS_SO)
	@mkdir -p $(BIN_DIR)
	$(CC) $^ -o $(BIN_DIR)/$@ $(LDFLAGS) $(LDFLAGS_SO)

all: $(EXEC) $(LIBRARY)

$(BUILD_DIR)/%.o: $(SOURCE_DIR)/%.cpp
	@mkdir -p $(BUILD_DIR)
	$(CC) $< -o $@ $(CCFLAGS)

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

