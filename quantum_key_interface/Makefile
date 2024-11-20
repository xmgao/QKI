# 使用的编译器
CXX = g++
# 编译器标志
CXXFLAGS = -std=c++17 -Wall -I$(INC_DIR)
LDFLAGS = -lpthread -lcrypto

# 要生成的可执行文件
TARGET = qki

# 源文件和头文件的路径
SRC_DIR = src
OBJ_DIR = obj
INC_DIR = include

# SRC_DIR目录中的所有.cpp文件
SRCS = $(wildcard $(SRC_DIR)/*.cpp $(SRC_DIR)/packet/*.cpp $(SRC_DIR)/qkdf/*.cpp)

# 对象文件：将源码文件路径转换为对象文件路径
OBJS = $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, \
        $(patsubst $(SRC_DIR)/packet/%.cpp, $(OBJ_DIR)/packet/%.o, \
        $(patsubst $(SRC_DIR)/qkdf/%.cpp, $(OBJ_DIR)/qkdf/%.o, $(SRCS))))

# 默认目标
all: $(TARGET)

# 链接对象文件以生成可执行文件
$(TARGET): $(OBJS)
	$(CXX) $(OBJS) -o $(TARGET) $(LDFLAGS)

# 编译.cpp文件为.o文件（放在obj目录中）
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(@D)  
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/packet/%.o: $(SRC_DIR)/packet/%.cpp
	@mkdir -p $(@D)  
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/qkdf/%.o: $(SRC_DIR)/qkdf/%.cpp
	@mkdir -p $(@D)  
	$(CXX) $(CXXFLAGS) -c $< -o $@

# 清理生成的文件
clean:
	rm -f $(OBJS) $(TARGET)

# 为Makefile创建的伪目标
.PHONY: all clean