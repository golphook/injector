#include "windows.h"




void* image_first_section(void* ad) {
    return IMAGE_FIRST_SECTION((IMAGE_NT_HEADERS*)ad);
}
