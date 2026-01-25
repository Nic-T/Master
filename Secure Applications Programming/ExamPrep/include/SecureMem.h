#ifndef SECUREMEM_H
#define SECUREMEM_H

#include <vector>
#include <string>

/**
 * @file SecureMem.h
 * @brief Small utilities for handling sensitive byte buffers in memory.
 *
 * - secureClear(): Overwrites memory and clears the container to reduce the
 *   lifetime of sensitive data in RAM.
 * - hexToBytes(): Convert a hex string (e.g., "deadbeef") into bytes.
 */

/// Overwrite and clear the contents of `v`.
void secureClear(std::vector<unsigned char>& v);

/// Convert a hex string (optionally with whitespace) into bytes. Returns
/// empty vector on parse error.
std::vector<unsigned char> hexToBytes(const std::string& hex);

#endif // SECUREMEM_H
