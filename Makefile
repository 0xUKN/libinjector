CC=g++
CCFLAGS=-c -fpic
LDFLAGS=-ldl -s
BUILD_DIR=build
SOURCE_DIR=src
BIN_DIR=bin
EXEC=library_injector
LIBRARY=libinjector.so


$(EXEC): directories TracedProcess.o Utils.o library_injector.o
	$(CC) $(BUILD_DIR)/TracedProcess.o $(BUILD_DIR)/Utils.o $(BUILD_DIR)/$(EXEC).o -o $(BIN_DIR)/$(EXEC) $(LDFLAGS)

$(LIBRARY): directories TracedProcess.o Utils.o
	$(CC) $(BUILD_DIR)/TracedProcess.o $(BUILD_DIR)/Utils.o -o $(BIN_DIR)/$(LIBRARY) $(LDFLAGS) -shared

all: directories $(EXEC) $(LIBRARY)
	@> /dev/null

directories:
	-mkdir -p $(BUILD_DIR)
	-mkdir -p $(BIN_DIR)

%.o:
	$(CC) $(SOURCE_DIR)/$*.cpp -o $(BUILD_DIR)/$@ $(CCFLAGS)
	
install:
	-cp $(BIN_DIR)/$(EXEC) /usr/bin/$(EXEC)
	-cp $(BIN_DIR)/$(LIBRARY) /usr/lib/$(LIBRARY)
	ldconfig

uninstall:
	-rm -f /usr/lib/$(LIBRARY) /usr/bin/$(EXEC)
	ldconfig

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
