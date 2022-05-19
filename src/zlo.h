/*
 * Copyright (C) 2022 0x80000000
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

#ifndef __ZLO_H
#define __ZLO_H

#include <vector>
#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>


/*
    *    src/zlo.h
    *    Date: 05/18/22
    *    Author: @xmmword
*/


namespace Zlo {
  class Dumper {
    public:
      [[maybe_unused]] auto DisplayLoadedLibraries(void) -> void;
      [[nodiscard]] auto ExportIterateNtdll(void) -> std::vector<BYTE *>;
      [[nodiscard]] auto DumpDllSystemCalls(const std::string lib) -> std::vector<BYTE *>;
  };
  
  class Scanner {
    public:
      auto CheckJmpHook(const std::string lib, const BYTE *function) -> void;
      [[nodiscard]] auto PatchTargetDLL(const std::string lib) -> bool;
  };
};

#endif