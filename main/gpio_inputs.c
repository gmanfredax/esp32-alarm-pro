// ===== File: main/gpio_inputs.c =====
// Scopo: soddisfare il riferimento in CMakeLists.txt.
// Le funzioni sono implementate in mcp23017.c; qui basta includere l'header.


#include "gpio_inputs.h"


// Nessuna implementazione qui: inputs_init() e inputs_read_all()
// sono definite in mcp23017.c. Questo file evita l'errore di CMake
// "Cannot find source file: main/gpio_inputs.c".