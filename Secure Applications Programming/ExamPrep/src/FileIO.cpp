#include "FileIO.h"
#include <fstream>
#include <iostream>

/*
 * Small file helpers implementation.
 * - readFile(): efficient full-file read using seek to get file size
 * - writeFile(): write bytes to disk (overwrites existing file)
 *
 * These helpers are intentionally simple — they print errors to stderr and
 * return empty results on failure so calling code can decide how to react.
 */

std::vector<unsigned char> readFile(const char* filename) {
    // Open file in binary mode at end to determine size quickly
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "Error opening: " << filename << std::endl;
        return {}; // Return empty vector on error
    }

    // Get size and rewind to start before reading
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    // Reserve exact size and perform a single read for speed
    std::vector<unsigned char> data(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char*>(data.data()), size)) {
        std::cerr << "Error reading: " << filename << std::endl;
        return {};
    }
    return data;
}

void writeFile(const char* filename, const std::vector<unsigned char>& data) {
    // Opens (and truncates) the file and writes the provided bytes.
    std::ofstream file(filename, std::ios::binary);
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
} 
