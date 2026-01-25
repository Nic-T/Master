#ifndef FILEIO_H
#define FILEIO_H

#include <vector>

/**
 * @file FileIO.h
 * @brief Minimal binary file I/O helpers used by the example code.
 *
 * These are intentionally small convenience functions for reading and
 * writing entire files into memory for exam-style examples.
 *
 * - readFile(): Returns the file bytes as a vector<unsigned char>. Returns
 *   an empty vector and prints an error to stderr on failure.
 * - writeFile(): Writes the provided bytes to disk (binary mode).
 */

/// Read entire file contents and return bytes. Empty vector on error.
std::vector<unsigned char> readFile(const char* filename);

/// Write the provided bytes to `filename` in binary mode.
void writeFile(const char* filename, const std::vector<unsigned char>& data);

#endif // FILEIO_H
