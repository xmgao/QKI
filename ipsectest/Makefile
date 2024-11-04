# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -std=c++17 -Wall -Iinclude

# Source files
SRCDIR = src
SOURCES = $(wildcard $(SRCDIR)/*.cpp)

# Object files
OBJDIR = obj
OBJECTS = $(patsubst $(SRCDIR)/%.cpp, $(OBJDIR)/%.o, $(SOURCES))

# Executables
EXECUTABLES = apppassive appproactive

# Default target
all: $(EXECUTABLES)

# apppassive target
apppassive: $(OBJDIR)/apppassive.o $(filter-out $(OBJDIR)/appproactive.o, $(OBJECTS))
	$(CXX) $^ -o $@

# appproactive target
appproactive: $(OBJDIR)/appproactive.o $(filter-out $(OBJDIR)/apppassive.o, $(OBJECTS))
	$(CXX) $^ -o $@

# Object file compilation
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(OBJDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean up
clean:
	rm -rf $(OBJDIR) $(EXECUTABLES)