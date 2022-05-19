/*
 * Copyright (C) 2022 xmmword
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "zlo.h"


/*
    *    src/zlo.cpp
    *    Date: 05/18/22
    *    Author: @xmmword
*/


namespace Zlo {
  
  /**
   * @brief Checks for the JMP opcode.
   * @param lib The library.
   * @param function The function.
   */
  
  auto Scanner::CheckJmpHook(const std::string lib, const BYTE *function) -> void {
    BYTE *bytes = nullptr;
    FARPROC address = nullptr;
    HMODULE library = LoadLibrary(lib.c_str());  
    
    if (!library)
      return;

    if (!(address = GetProcAddress(library, (CHAR *)function)))
      return;

#ifdef DEBUG
  std::cout << "[DEBUG]: Scanning for hooks in " << function << "!" << std::endl;
#endif

    bytes = reinterpret_cast<BYTE *>(address);

    for (DWORD i = 0; i < 4; i++)
      if (bytes[i] == 0xE9)
        std::cout << "[zlo]: " << function << " is hooked!" << std::endl;

    CloseHandle(library);
  }

  /**
   * @brief Patches a given DLL.
   * @param lib The library.
   * @returns True if the DLL was patched, false if otherwise.
   */

  [[nodiscard]] auto Scanner::PatchTargetDLL(const std::string lib) -> bool {
    DWORD old = 0;
    MODULEINFO mod;

    LPVOID addr = nullptr, base_address = nullptr;
    std::string dll_path = "C:\\Windows\\System32\\" + lib;

    PIMAGE_DOS_HEADER dh = nullptr;
    PIMAGE_NT_HEADERS nt_h = nullptr;

    /**
     * Opening a handle.
     */ 

    HMODULE library = GetModuleHandleA(lib.c_str());
    HANDLE pid = GetCurrentProcess(), library_path = nullptr, library_mapping = nullptr;

    /**
     * Retrieving information about the module.
     */ 

    if (!library || GetModuleInformation(pid, library, &mod, sizeof(mod)) == 0)
      return false;
    
    base_address = reinterpret_cast<LPVOID>(mod.lpBaseOfDll);
    library_path = CreateFileA(dll_path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    library_mapping = CreateFileMapping(library_path, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL), addr = MapViewOfFile(library_mapping, FILE_MAP_READ, 0, 0, 0);

    dh = reinterpret_cast<PIMAGE_DOS_HEADER>(base_address);
    nt_h = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD_PTR>(base_address) + dh->e_lfanew);

    /**
     * Checking for invalid signatures.
     */ 

    if (dh->e_magic != IMAGE_DOS_SIGNATURE || nt_h->Signature != IMAGE_NT_SIGNATURE)
      return false;

    for (DWORD i = 0; i < nt_h->FileHeader.NumberOfSections; i++) {
      PIMAGE_SECTION_HEADER header = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<DWORD_PTR>(IMAGE_FIRST_SECTION(nt_h)) + (IMAGE_SIZEOF_SECTION_HEADER * i));

      if (strncmp(reinterpret_cast<char *>(header->Name), ".text", 5) != 0) 
        continue;

      if (VirtualProtect(reinterpret_cast<LPVOID>(reinterpret_cast<DWORD_PTR>(base_address) + reinterpret_cast<DWORD_PTR>(header->VirtualAddress)), header->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &old) == 0)
        return false;

      /**
       * Overwriting and patching the .text section.
       */ 

      memcpy(reinterpret_cast<LPVOID>(reinterpret_cast<DWORD_PTR>(base_address) + reinterpret_cast<DWORD_PTR>(header->VirtualAddress)), reinterpret_cast<LPVOID>(reinterpret_cast<DWORD_PTR>(addr) + reinterpret_cast<DWORD_PTR>(header->VirtualAddress)), header->Misc.VirtualSize);

      if (VirtualProtect((LPVOID)((DWORD_PTR)base_address + (DWORD_PTR)header->VirtualAddress), header->Misc.VirtualSize, old, &old) == 0)
        return false;
    }
    
    CloseHandle(pid);
    FreeLibrary(library);

    CloseHandle(library_path);
    CloseHandle(library_mapping);

    return true;
  }

  /**
   * @brief Displays the loaded libraries.
   */

  [[maybe_unused]] auto Dumper::DisplayLoadedLibraries(void) -> void {
    MODULEENTRY32 entry = {.dwSize=sizeof(MODULEENTRY32)};
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);

    if (!Module32First(snapshot, &entry))
      return;

    std::cout << "[DEBUG]: Listed loaded libraries!" << std::endl;

    do {
      std::cout << "Library: " << entry.szExePath << std::endl;
    } while (Module32Next(snapshot, &entry));

    CloseHandle(snapshot);
  }
  
  /**
   * @brief Exports function names from ntdll.dll.
   * @returns A vector containing the exported information.
   */

  [[nodiscard]] auto Dumper::ExportIterateNtdll(void) -> std::vector<BYTE *> {
    std::vector<BYTE *> exported_data;

    PDWORD temp = nullptr;
    PIMAGE_DOS_HEADER dh = nullptr;
    PIMAGE_NT_HEADERS nt_h = nullptr;
    PIMAGE_EXPORT_DIRECTORY directory = nullptr;

    /**
     * Opening a handle.
     */

    HANDLE library = LoadLibrary("ntdll.dll");
    if (!library)
      return exported_data;

    dh = reinterpret_cast<PIMAGE_DOS_HEADER>(library), nt_h = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE *>(library) + dh->e_lfanew);
    directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<BYTE *>(library) + nt_h->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    temp = reinterpret_cast<PDWORD>(reinterpret_cast<BYTE *>(library) + directory->AddressOfNames);

    /**
     * Checking for invalid signatures.
     */ 

    if (dh->e_magic != IMAGE_DOS_SIGNATURE || nt_h->Signature != IMAGE_NT_SIGNATURE || directory->NumberOfFunctions == 0)
      return exported_data;

    /**
     * Iterating over the function names.
     */ 

    for (DWORD i = 0; i < directory->NumberOfNames; i++)
      if (memcmp(reinterpret_cast<BYTE *>(library + temp[i]), "Nt", 2) == 0 || memcmp(reinterpret_cast<BYTE *>(library + temp[i]), "Zw", 2) == 0)
        exported_data.push_back(reinterpret_cast<BYTE *>(library + temp[i]));

    CloseHandle(library);
    return exported_data;
  }

  /**
   * @brief Exports function names from a given library.
   * @param lib The library.
   * @returns A vector containing the dumped system calls.
   */
  
  [[nodiscard]] auto Dumper::DumpDllSystemCalls(const std::string lib) -> std::vector<BYTE *> {
    std::vector<BYTE *> syscalls;

    PWORD addr = nullptr;  
    PDWORD function = nullptr, name = nullptr;
    BYTE *base = nullptr, *temp = nullptr, *temp_function = nullptr;

    HANDLE library = nullptr;
    PIMAGE_DOS_HEADER dh = nullptr;
    PIMAGE_NT_HEADERS nt_h = nullptr;
    PIMAGE_EXPORT_DIRECTORY directory = nullptr;

    /**
     * Opening a handle.
     */ 

    if (!(library = LoadLibraryExA(lib.c_str(), NULL, LOAD_LIBRARY_AS_DATAFILE)))
      return syscalls;

    base = reinterpret_cast<BYTE *>(library), dh = reinterpret_cast<PIMAGE_DOS_HEADER>(base), nt_h = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dh->e_lfanew);
    directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + nt_h->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    /**
     * Checking for invalid signatures.
     */ 

    if (dh->e_magic != IMAGE_DOS_SIGNATURE || nt_h->Signature != IMAGE_NT_SIGNATURE || directory->NumberOfFunctions == 0)
      return syscalls;
    
    name = reinterpret_cast<PDWORD>(reinterpret_cast<BYTE *>(base) + directory->AddressOfNames);
    addr = reinterpret_cast<PWORD>(reinterpret_cast<BYTE *>(base) + directory->AddressOfNameOrdinals);
    function = reinterpret_cast<PDWORD>(reinterpret_cast<BYTE *>(base) + directory->AddressOfFunctions);

    /**
     * Iterating over the functions.
     */ 

    for (DWORD i = 0; i < directory->NumberOfFunctions; i++)
      if (memcmp(reinterpret_cast<BYTE *>(base + name[i]), "Nt", 2) == 0 || memcmp(reinterpret_cast<BYTE *>(base + name[i]), "Zw", 2) == 0)
        syscalls.push_back(reinterpret_cast<BYTE *>(base + name[i]));

    CloseHandle(library);
    return syscalls;
  }
};

/**
 * @brief Initializes the dumper and scanner.
 * @returns EXIT_SUCCESS;
 */

auto main(void) -> std::int32_t {
  using Zlo::Dumper;
  using Zlo::Scanner;
  
  std::vector<BYTE *> ntFunctions = Dumper().ExportIterateNtdll(), kernelFunctions = Dumper().DumpDllSystemCalls("kernel32.dll");
  std::vector<BYTE *> kernelbaseFunctions = Dumper().DumpDllSystemCalls("kernelbase.dll"), msvcrtFunctions = Dumper().DumpDllSystemCalls("msvcrt.dll");

#ifdef DEBUG
  Dumper().DisplayLoadedLibraries();
#endif

  if (!ntFunctions.empty())
    for (auto function: ntFunctions)
      Scanner().CheckJmpHook("ntdll.dll", function);

  if (!kernelFunctions.empty())
    for (auto function: kernelFunctions)
      Scanner().CheckJmpHook("kernel32.dll", function);

  if (!kernelbaseFunctions.empty())
    for (auto function: kernelFunctions)
      Scanner().CheckJmpHook("kernelbase.dll", function);

  if (!msvcrtFunctions.empty())
    for (auto function: kernelFunctions)
      Scanner().CheckJmpHook("msvcrt.dll", function);

  if (Scanner().PatchTargetDLL("ntdll.dll") && Scanner().PatchTargetDLL("kernel32.dll") && Scanner().PatchTargetDLL("kernelbase.dll") && Scanner().PatchTargetDLL("msvcrt.dll"))
    std::cout << "[zlo]: All hooks have successfully been patched!" << std::endl;
  else
    std::cout << "[zlo]: Failed to patch hooks!" << std::endl;

  return EXIT_SUCCESS;
}