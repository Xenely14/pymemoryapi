from ctypes.wintypes import *
from typing import Any
import struct
import ctypes
import locale
import os
import re

# Coded by Xenely

# WinAPI флаги
PROCESS_ALL_ACCESS = 0x001F0FFF
PROCESS_VM_OPERATION = 0x0008
LIST_MODULES_ALL = 0x003
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020

MEM_COMMIT = 0x00001000

PAGE_EXECUTE_READ = 0x0020
PAGE_EXECUTE_READWRITE = 0x0040
PAGE_READONLY = 0x002
PAGE_READWRITE = 0x004

MAX_PATH = 260

# WinAPI обозначения типов
ctypes.windll.kernel32.OpenProcess.restype = HANDLE
ctypes.windll.kernel32.VirtualAllocEx.restype = LPVOID


def heximate_bytes(bytearray: bytes) -> str:
    r"""Возвращает массив байтов в ввиде строчного паттерна в стиле Cheat Engine.

    Return byte array as a string pattern like in Cheat Engine.

    >>> from pymemoryapi import *
    >>> heximate_bytes(b"\xBA\xFF\x05\xCC")
    "BA FF 05 CC"
    """

    heximate_bytes = bytearray.hex()
    return (" ".join([heximate_bytes[i: i + 2] for i in range(0, len(heximate_bytes), 2)])).strip().upper()


def mov_difference(offset: int) -> bytes:
    r"""Возвращает ассемблерное представление mov оффсета.

    Return assembly bytes of mov offset.

    >>> from pymemoryapi import *
    >>> # 0x64FF000 = to_address
    >>> # 0x4246724 = from_address
    >>> mov_difference(to_add - from_add)
    b'\xdc\x88+\x02'
    """

    hex_offset = ''
    jump_bytecode = b''

    if offset < 0:
        hex_offset = hex(0xFFFF_FFFF_FFFF_FFFF + offset + 1)[10:]
        while len(hex_offset) != 8:
            hex_offset = '0' + hex_offset
        hex_offset = "".join(reversed([hex_offset[i: i + 2] for i in range(0, len(hex_offset), 2)]))

    else:
        hex_offset = hex(offset)[2:]
        while len(hex_offset) != 8:
            hex_offset = '0' + hex_offset
        hex_offset = "".join(reversed([hex_offset[i: i + 2] for i in range(0, len(hex_offset), 2)]))

    jump_bytecode += bytes.fromhex(hex_offset)
    return jump_bytecode


def list_processes_ids() -> list:
    """Возвращает список ID всех активных процессов.

    Return ID list of all active processes.

    >>> from pymemoryapi import *
    >>> list_processes_ids()
    [0, 2560, 4, ..., 4088]
    """

    quantity = 32
    while True:
        process_ids = (DWORD * quantity)()
        quantity_buffer = ctypes.sizeof(process_ids)
        bytes_returned = DWORD()
        if ctypes.windll.Psapi.EnumProcesses(ctypes.byref(process_ids), quantity_buffer, ctypes.byref(bytes_returned)):
            if bytes_returned.value < quantity_buffer:
                return list(set(process_ids))
            else:
                quantity *= 2


def list_processes_names() -> list:
    """Возвращает список имен всех активных процессов.

    Return name list of all active processes.

    >>> from pymemoryapi import *
    >>> list_processes_names()
    ['opera.exe', 'svchost.exe', 'Discord.exe', ..., 'RuntimeBroker.exe']
    """

    quantity = 32
    processes_ids_list = []
    while True:
        process_ids = (DWORD * quantity)()
        quantity_buffer = ctypes.sizeof(process_ids)
        bytes_returned = DWORD()
        if ctypes.windll.Psapi.EnumProcesses(ctypes.byref(process_ids), quantity_buffer, ctypes.byref(bytes_returned)):
            if bytes_returned.value < quantity_buffer:
                processes_ids_list = list(set(process_ids))
                break
            else:
                quantity *= 2

    processes_names = []
    for process_id in processes_ids_list:
        image_file_name = (ctypes.c_char * MAX_PATH)()
        process_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
        if ctypes.windll.psapi.GetProcessImageFileNameA(process_handle, image_file_name, MAX_PATH) > 0:
            filename = os.path.basename(image_file_name.value).decode()
            processes_names.append(filename)

    return processes_names


def list_processes() -> list:
    """Возвращает список ID и имен всех активных процессов.

    Return ID's and names list of all active processes.

    >>> from pymemoryapi import *
    >>> list_processes()
    [('opera.exe', 20484), ('svchost.exe', 13832), ..., ('RuntimeBroker.exe', 33264)]
    """

    quantity = 32
    processes_ids_list = []
    while True:
        process_ids = (DWORD * quantity)()
        quantity_buffer = ctypes.sizeof(process_ids)
        bytes_returned = DWORD()
        if ctypes.windll.Psapi.EnumProcesses(ctypes.byref(process_ids), quantity_buffer, ctypes.byref(bytes_returned)):
            if bytes_returned.value < quantity_buffer:
                processes_ids_list = list(set(process_ids))
                break
            else:
                quantity *= 2

    processes = []
    for process_id in processes_ids_list:
        try:
            image_file_name = (ctypes.c_char * MAX_PATH)()
            process_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
            if ctypes.windll.psapi.GetProcessImageFileNameA(process_handle, image_file_name, MAX_PATH) > 0:
                filename = os.path.basename(image_file_name.value).decode()
                processes.append((filename, process_id))
        except Exception:
            pass

    return processes


def is_64bit(process_handle: int) -> bool:
    """Проверяет является ли процесс 64-битным. Возращает булево значение.

    Check if process is 64 bit. Retun bool value.

    >>> from pymemoryapi import *
    >>> process = Process("Discord.exe")
    >>> is_64bit(process.handle)
    True
    """

    wow_64 = ctypes.c_long()
    ctypes.windll.kernel32.IsWow64Process(process_handle, ctypes.byref(wow_64))
    return bool(wow_64)


def table_memory(process: object, address: int, rows: int, row_length: int = 24) -> None:
    """Строит байт таблицу как в Cheat Engine по заданому адресу.

    Print table of bytecode like in Cheat Engine by given address.
    """

    try:
        for i in range(rows):
            row_bytes = process.read_bytes(address + (i * row_length), row_length)
            print(hex(address + (i * row_length))[2:len(hex(address + (i * row_length)))].upper() + ' | ' + heximate_bytes(row_bytes))
    except Exception:
        MemoryAPIException("Невозможно построить таблицу по заданому адресу.")


def list_modules(process_handle: int) -> list:
    """Возвращает список всех подключенных модулей к процессу.

    Return list of connected to process modules.

    >>> from pymemoryapi import *
    >>> process = Process("Discord.exe")
    >>> list_modules(process.handle)
    ['Discord.exe', 'ntdll.dll', 'KERNEL32.DLL', ..., 'wow64cpu.dll']
    """

    hModules = (ctypes.c_void_p * 1024)()
    process_module_success = ctypes.windll.psapi.EnumProcessModulesEx(process_handle, ctypes.byref(hModules), ctypes.sizeof(hModules), ctypes.byref(ctypes.c_ulong()), LIST_MODULES_ALL)
    if process_module_success:
        modules = []
        hModules = iter(m for m in hModules if m)
        for hModule in hModules:
            module_info = MODULE(process_handle)
            ctypes.windll.psapi.GetModuleInformation(process_handle, ctypes.c_void_p(hModule), ctypes.byref(module_info), ctypes.sizeof(module_info))
            modules.append(module_info.name)
        return modules


def virtual_alloc_ex(process_handle: int, bytes_length: int) -> int:
    """Выделяет указаное количество байт в памяти процесса.

    Allocate memory in selected process by given byte length.

    >>> from pymemoryapi import *
    >>> process = Process("Discord.exe")
    >>> virtual_alloc_ex(process.handle, 4096)
    0xdef0000
    """

    allocation_address = ctypes.windll.kernel32.VirtualAllocEx(process_handle, 0, bytes_length, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    if not allocation_address:
        raise MemoryAPIException("Handle процесса передан неверно, или размер буфера некорректен.")
    else:
        return allocation_address


def virtual_query_ex(process_handle: int, address: int) -> object:
    """Возвращает объект MEMORY_BASIC_INFORMATION, содержащий информацию о регионе памяти по адресу.

    Return MEMORY_BASIC_INFORMATION object, containing information about memory region by given address.

    >>> from pymemoryapi import *
    >>> process = Process("Notepad++.exe")
    >>> region_info = virtual_query_ex(process.handle, 0x80FCC8)
    >>> base, size = region_info.BaseAddress, region_info.RegionSize
    (0x80f000, 4096)
    """

    memory_information = MEMORY_BASIC_INFORMATION()
    ctypes.windll.kernel32.VirtualQueryEx(process_handle, ctypes.cast(address, ctypes.c_char_p), ctypes.byref(memory_information), ctypes.sizeof(memory_information))
    return memory_information


class MemoryAPIException(Exception):
    """Базовый класс ошибок MemoryAPI.

    Basic MemoryAPI exception class.
    """
    pass


class MEMORY_BASIC_INFORMATION(ctypes.Structure):

    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong),
        ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", ctypes.c_ulong),
        ("align1", ctypes.c_ulong),
        ("RegionSize", ctypes.c_ulonglong),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
        ("align2", ctypes.c_ulong),
    ]


class MODULE(ctypes.Structure):

    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("SizeOfImage", ctypes.c_ulong),
        ("EntryPoint", ctypes.c_void_p),
    ]

    def __init__(self, handle):
        self.process_handle = handle

    @property
    def name(self):
        modname = ctypes.c_buffer(MAX_PATH)
        ctypes.windll.psapi.GetModuleBaseNameA(self.process_handle, ctypes.c_void_p(self.BaseAddress), modname, ctypes.sizeof(modname))
        return modname.value.decode(locale.getpreferredencoding())

    @property
    def filename(self):
        _filename = ctypes.c_buffer(MAX_PATH)
        ctypes.windll.psapi.GetModuleFileNameExA(self.process_handle, ctypes.c_void_p(self.BaseAddress), _filename, ctypes.sizeof(_filename))
        return _filename.value.decode(locale.getpreferredencoding())


class TrampolineHook:
    """Класс cодержащий методы, необходимые для создание хуков.

    Class containing methods required to set hooks.

    >>> from pymemoryapi import *
    >>> process = Process(process_name="Terraria.exe")
    >>> health_instruction = process.raw_pattern_scan(0, 0xF0000000, "DB 86 E4 03 00 00 D9 5D F8 D9 45 F8", return_first_found=True)
    >>> health_hook = pymemoryapi.TrampolineHook(process, health_instruction, 18, 4096, use_x64_registers=False)
    """

    def unhook(self) -> None:
        """Убирает хук и удаляет объект.

        Remove hook and hook object.
        """

        self.__process.write_bytes(self.__instruction_address, self.original_code)

    def clear(self) -> None:
        """Очищает байткод, оставляя только оригинальный код.

        Clear bytecode, leaving only original code.
        """

        self.hook_bytecode = self.original_code + self.__backward__jump
        while len(self.hook_bytecode) != self.__alloc_buffer_size:
            self.hook_bytecode += b'\x00'
        else:
            self.__process.write_bytes(self.__instruction_address, self.hook_bytecode)

    def insert_bytecode(self, bytecode: str) -> None:
        """Подставляет данный байткод перед оригинальным кодом.

        Instern given bytecode before the original code.

        >>> # Бесконечные хп в Terraria
        >>> # Infinite HP in Terraria
        >>> from pymemoryapi import *
        >>> process = Process(process_name="Terraria.exe")
        >>> health_instruction = process.raw_pattern_scan(0, 0xF0000000, "DB 86 E4 03 00 00 D9 5D F8 D9 45 F8", return_first_found=True)
        >>> health_hook = pymemoryapi.TrampolineHook(process, health_instruction, 18, 4096, use_x64_registers=False)
        >>> # C7 86 E4 03 00 00 39 05 00 00 -> mov [esi + 000003E4], (int)1337
        >>> health_hook.insert_bytecode("C7 86 E4 03 00 00 39 05 00 00")

        """
        insert_bytecode = bytecode.strip().split(" ")
        insert_bytecode = bytes.fromhex("".join(insert_bytecode))
        self.hook_bytecode = insert_bytecode + self.original_code + self.__backward__jump
        self.__process.write_bytes(self.alloc, self.hook_bytecode)

    def __init__(self, process: object, instruction_address: int, instruction_lenght: int, alloc_buffer_size: int, use_x64_registers: bool = True) -> None:

        if use_x64_registers and instruction_lenght < 12:
            raise MemoryAPIException("Длина инструкции должна быть не менее 12.")
        elif not use_x64_registers and instruction_lenght < 7:
            raise MemoryAPIException("Длина инструкции должна быть не менее 7.")

        self.__process = process
        self.__instruction_address = instruction_address
        self.__alloc_buffer_size = alloc_buffer_size
        self.__use_x64 = use_x64_registers

        self.hook_bytecode = b""

        self.alloc = virtual_alloc_ex(process.handle, alloc_buffer_size)

        self.original_code = process.read_bytes(instruction_address, instruction_lenght)
        self.hook_bytecode += self.original_code

        if self.__use_x64:

            self.__backward = hex(instruction_address + instruction_lenght)[2:]
            while len(self.__backward) != 16:
                self.__backward = '0' + self.__backward

            self.__backward = "".join(reversed([self.__backward[i: i + 2] for i in range(0, len(self.__backward), 2)]))
            # 48 B8 -> mov rax, address
            # FF E0 - jmp rax
            self.__backward__jump = b'\x48\xb8' + bytes.fromhex(self.__backward) + b'\xff\xe0'
            self.hook_bytecode += self.__backward__jump

            self.__forward = hex(self.alloc)[2:]
            while len(self.__forward) != 16:
                self.__forward = '0' + self.__forward

            self.__forward = "".join(reversed([self.__forward[i: i + 2] for i in range(0, len(self.__forward), 2)]))
            # 48 B8 -> mov rax, address
            # FF E0 - jmp rax
            self.__forward_jump = b'\x48\xb8' + bytes.fromhex(self.__forward) + b'\xff\xe0'

            while len(self.__forward_jump) != instruction_lenght:
                self.__forward_jump += b'\x90'

            process.write_bytes(self.alloc, self.hook_bytecode)
            process.write_bytes(instruction_address, self.__forward_jump)

        else:

            self.__backward = hex(instruction_address + instruction_lenght)[2:]
            while len(self.__backward) != 8:
                self.__backward = '0' + self.__backward

            self.__backward = "".join(reversed([self.__backward[i: i + 2] for i in range(0, len(self.__backward), 2)]))
            # B8 -> mov eax, address
            # FF E0 - jmp eax
            self.__backward__jump = b'\xb8' + bytes.fromhex(self.__backward) + b'\xff\xe0'
            self.hook_bytecode += self.__backward__jump

            self.__forward = hex(self.alloc)[2:]
            while len(self.__forward) != 8:
                self.__forward = '0' + self.__forward

            self.__forward = "".join(reversed([self.__forward[i: i + 2] for i in range(0, len(self.__forward), 2)]))
            # B8 -> mov eax, address
            # FF E0 - jmp eax
            self.__forward_jump = b'\xb8' + bytes.fromhex(self.__forward) + b'\xff\xe0'

            while len(self.__forward_jump) != instruction_lenght:
                self.__forward_jump += b'\x90'

            process.write_bytes(self.alloc, self.hook_bytecode)
            process.write_bytes(instruction_address, self.__forward_jump)


class Process:
    """Базовый класс MemoryAPI. Содержит методы, необходимые для работы с ОЗУ процесса.

    Basic MemoryAPI class, containing methods required to work with RAM of process.

    >>>from pymemoryapi import *
    >>> process = Process(process_name="Terraria.exe")
    >>> process = Process(pid=2204)
    >>> # Можно создать без аргументов
    >>> # Can create without args
    >>> process = Process()
    """

    def __init__(self, process_name: str = None, pid: int = None) -> None:

        if not process_name and not pid:
            raise MemoryAPIException("Процесс должен быть подключен при помощи имени или ID.")

        # Подключение по названию процесса
        if process_name and not pid:

            introduced_process_name = process_name
            if not introduced_process_name.endswith('.exe'):
                introduced_process_name += ".exe"

            processes = list_processes()
            for process_name_iter, process_id_iter in processes:
                if process_name_iter.lower() == introduced_process_name.lower():
                    self.pid = process_id_iter
                    self.name = process_name_iter
                    self.handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, process_id_iter)
                    break
            else:
                raise MemoryAPIException("Процесс с данным именем не найден.")

        # Подключение по ID процесса
        if pid and not process_name:

            process_id = pid

            processes = list_processes()
            for process_name_iter, process_id_iter in processes:
                if process_id == process_id_iter:
                    self.pid = process_id_iter
                    self.name = process_name_iter
                    self.handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, process_id_iter)
                    break
            else:
                raise MemoryAPIException("Процесс с данным ID не найден.")

        if process_name and pid:
            raise MemoryAPIException("Класс принимает в конструктор только process_name или только pid.")

    def get_module_info(self, module_name: str) -> object:
        """Возвращает объект MODULE, содержащий информацию о модуле.

        return MODULE object, containing informations aboute given module.

        >>> from pymemoryapi import *
        >>> process = Process("Discord.exe")
        >>> kernel_module = process.get_module_info("kernel32.dll")
        >>> kernel_info = (kernel_module.BaseAddress, kernel_module.SizeOfImage, kernel_module.EntryPoint)
        (0x757b0000, 0xf0000, 0x757c77c0)
        """

        hModules = (ctypes.c_void_p * 1024)()
        process_module_success = ctypes.windll.psapi.EnumProcessModulesEx(self.handle, ctypes.byref(hModules), ctypes.sizeof(hModules), ctypes.byref(ctypes.c_ulong()), LIST_MODULES_ALL)
        if process_module_success:
            hModules = iter(i for i in hModules if i)
            for hModule in hModules:
                module_info = MODULE(self.handle)
                ctypes.windll.psapi.GetModuleInformation(self.handle, ctypes.c_void_p(hModule), ctypes.byref(module_info), ctypes.sizeof(module_info))
                if module_name.lower() == module_info.name.lower():
                    return module_info

        raise MemoryAPIException("Модуль с указаным именем не найден.")

    # Сканер сигнатур
    def pattern_scan(self, start_address: int, end_address: int, pattern: str, return_first_found: bool = False) -> Any:
        """Ищет адреса с заданными байтам в заданном диапазоне.

        Search address with given bytes in given region.

        >>> # Получение списка адресов
        >>> # Для получения первого подходящего адреса передаем аргумент return_first_found=True
        >>> # В случае с одиночным поиском возвращает int или None вместо списка
        >>> # Getting list of addresses
        >>> # For getting first suitable address give extra argument return_first_found=True
        >>> # Return int or None if work with single address search
        >>> from pymemoryapi import *
        >>> process = Process(process_name="Notepad++.exe")
        >>> found_addresses = process.pattern_scan(0, 0xFFFFFF, "14 00 00 00 FF FF")
        [0x80fcc8, 0x80fdac]
        """

        scan_region = start_address
        self.__bytes_pattern = pattern.strip().split(" ")

        if not pattern.count("?"):
            self.__bytes_pattern = bytes.fromhex("".join(self.__bytes_pattern))
        else:
            temp_pattern = b""
            for byte in self.__bytes_pattern:
                if byte == "??":
                    temp_pattern += b'.'
                else:
                    temp_pattern += bytes.fromhex(byte)
            self.__bytes_pattern = temp_pattern

        self.__scan_sections = []
        allowed_protections = [PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PAGE_READONLY]
        while scan_region < end_address:
            memory_region_information = virtual_query_ex(self.handle, scan_region)
            scan_region = memory_region_information.BaseAddress + memory_region_information.RegionSize
            if not (memory_region_information.State != MEM_COMMIT or memory_region_information.Protect not in allowed_protections):
                self.__scan_sections.append((memory_region_information.BaseAddress, memory_region_information.RegionSize))

        addresses = []
        for section in self.__scan_sections:
            try:
                self.__page = self.read_bytes(section[0], section[1])
                if not return_first_found:
                    for match in re.finditer(self.__bytes_pattern, self.__page, re.DOTALL):
                        addresses.append(section[0] + match.span()[0])
                else:
                    for match in re.finditer(self.__bytes_pattern, self.__page, re.DOTALL):
                        return section[0] + match.span()[0]
            except Exception:
                pass
        if return_first_found:
            return None
        else:
            return addresses

    def raw_pattern_scan(self, start_address: int, end_address: int, pattern: str, return_first_found: bool = False) -> Any:
        """Ищет адреса с заданными байтам в заданном диапазоне. Работает с rb"bytes" вместо b"bytes".

        Search address with given bytes in given region. Work with rb"bytes" instead of b"bytes".

        >>> # Получение списка адресов
        >>> # Для получения первого подходящего адреса передаем аргумент return_first_found=True
        >>> # В случае с одиночным поиском возвращает int или None вместо списка
        >>> # Getting list of addresses
        >>> # For getting first suitable address give extra argument return_first_found=True
        >>> # Return int or None if work with single address search
        >>> from pymemoryapi import *
        >>> process = Process(process_name="Notepad++.exe")
        >>> found_addresses = process.raw_pattern_scan(0, 0xFFFFFF, "14 00 00 00 FF FF")
        [0x80fcc8, 0x80fdac]
        """

        scan_region = start_address

        self.__bytes_pattern = pattern.strip().split(" ")

        if not pattern.count("?"):
            self.__bytes_pattern = bytes.fromhex("".join(self.__bytes_pattern))
        else:
            temp_pattern = b""
            for byte in self.__bytes_pattern:
                if byte == "??":
                    temp_pattern += b'.'
                else:
                    temp_pattern += b'\\' + 'x'.encode() + byte.encode()
            self.__bytes_pattern = temp_pattern

        self.__scan_sections = []
        allowed_protections = [PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PAGE_READONLY]
        while scan_region < end_address:
            memory_region_information = virtual_query_ex(self.handle, scan_region)
            scan_region = memory_region_information.BaseAddress + memory_region_information.RegionSize
            if not (memory_region_information.State != MEM_COMMIT or memory_region_information.Protect not in allowed_protections):
                self.__scan_sections.append((memory_region_information.BaseAddress, memory_region_information.RegionSize))

        addresses = []
        for section in self.__scan_sections:
            try:
                self.__page = self.read_bytes(section[0], section[1])
                if not return_first_found:
                    for match in re.finditer(self.__bytes_pattern, self.__page, re.DOTALL):
                        addresses.append(section[0] + match.span()[0])
                else:
                    for match in re.finditer(self.__bytes_pattern, self.__page, re.DOTALL):
                        return section[0] + match.span()[0]
            except Exception:
                pass
        if return_first_found:
            return None
        else:
            return addresses

    # Чтение памяти
    def read_bytes(self, address: int, length: int) -> bytes:
        r"""Читает заданое количество байт по данному адресу.

        Read given length of bytes by given address.

        >>> from pymemoryapi import *
        >>> process = Process(process_name="Notepad++.exe")
        >>> value = process.read_bytes(0x80FCC8, 4)
        b'\x14\x00\x00\x00'
        """

        buffer = ctypes.create_string_buffer(length)
        bytes_read = ctypes.c_size_t()
        ctypes.windll.kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(address), ctypes.byref(buffer), length, ctypes.byref(bytes_read))
        return buffer.raw

    def read_short(self, address: int) -> int:
        """Читает 2 байта по данному адресу.

        Read 2 bytes by given address.

        >>> from pymemoryapi import *
        >>> process = Process(process_name="Notepad++.exe")
        >>> value = process.read_short(0x80FCC8)
        20
        """

        buffer = ctypes.create_string_buffer(2)
        bytes_read = ctypes.c_size_t()
        ctypes.windll.kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(address), ctypes.byref(buffer), 2, ctypes.byref(bytes_read))
        return struct.unpack('<h', buffer.raw)[0]

    def read_ushort(self, address: int) -> int:
        """Читает 2 байта по данному адресу.

        Read 2 bytes by given address.

        >>> from pymemoryapi import *
        >>> process = Process(process_name="Notepad++.exe")
        >>> value = process.read_ushort(0x80FCC8)
        20
        """

        buffer = ctypes.create_string_buffer(2)
        bytes_read = ctypes.c_size_t()
        ctypes.windll.kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(address), ctypes.byref(buffer), 2, ctypes.byref(bytes_read))
        return struct.unpack('<H', buffer.raw)[0]

    def read_int(self, address: int) -> int:
        """Читает 4 байта по данному адресу.

        Read 4 bytes by given address.

        >>> from pymemoryapi import *
        >>> process = Process(process_name="Notepad++.exe")
        >>> value = process.read_int(0x80FCC8)
        20
        """

        buffer = ctypes.create_string_buffer(4)
        bytes_read = ctypes.c_size_t()
        ctypes.windll.kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(address), ctypes.byref(buffer), 4, ctypes.byref(bytes_read))
        return struct.unpack('<i', buffer.raw)[0]

    def read_uint(self, address: int) -> int:
        """Читает 4 байта по данному адресу.

        Read 4 bytes by given address.

        >>> from pymemoryapi import *
        >>> process = Process(process_name="Notepad++.exe")
        >>> value = process.read_uint(0x80FCC8)
        20
        """

        buffer = ctypes.create_string_buffer(4)
        bytes_read = ctypes.c_size_t()
        ctypes.windll.kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(address), ctypes.byref(buffer), 4, ctypes.byref(bytes_read))
        return struct.unpack('<I', buffer.raw)[0]

    def read_long(self, address: int) -> int:
        """Читает 4 байта по данному адресу.

        Read 4 bytes by given address.

        >>> from pymemoryapi import *
        >>> process = Process(process_name="Notepad++.exe")
        >>> value = process.read_long(0x80FCC8)
        20
        """

        buffer = ctypes.create_string_buffer(4)
        bytes_read = ctypes.c_size_t()
        ctypes.windll.kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(address), ctypes.byref(buffer), 4, ctypes.byref(bytes_read))
        return struct.unpack('<l', buffer.raw)[0]

    def read_ulong(self, address: int) -> int:
        """Читает 4 байта по данному адресу.

        Read 4 bytes by given address.

        >>> from pymemoryapi import *
        >>> process = Process(process_name="Notepad++.exe")
        >>> value = process.read_ulong(0x80FCC8)
        20
        """

        buffer = ctypes.create_string_buffer(4)
        bytes_read = ctypes.c_size_t()
        ctypes.windll.kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(address), ctypes.byref(buffer), 4, ctypes.byref(bytes_read))
        return struct.unpack('<L', buffer.raw)[0]

    def read_longlong(self, address: int) -> int:
        """Читает 8 байтов по данному адресу.

        Read 8 bytes by given address.

        >>> from pymemoryapi import *
        >>> process = Process(process_name="Notepad++.exe")
        >>> value = process.read_longlong(0x80FCC8)
        -4294967276
        """

        buffer = ctypes.create_string_buffer(8)
        bytes_read = ctypes.c_size_t()
        ctypes.windll.kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(address), ctypes.byref(buffer), 8, ctypes.byref(bytes_read))
        return struct.unpack('<q', buffer.raw)[0]

    def read_ulonglong(self, address: int) -> int:
        """Читает 8 байтов по данному адресу.

        Read 8 bytes by given address.

        >>> from pymemoryapi import *
        >>> process = Process(process_name="Notepad++.exe")
        >>> value = process.read_ulonglong(0x80FCC8)
        18446744069414584340
        """

        buffer = ctypes.create_string_buffer(8)
        bytes_read = ctypes.c_size_t()
        ctypes.windll.kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(address), ctypes.byref(buffer), 8, ctypes.byref(bytes_read))
        return struct.unpack('<Q', buffer.raw)[0]

    def read_float(self, address: int) -> float:
        """Читает 4 байта по данному адресу.

        Read 4 bytes by given address.
        >>> from pymemoryapi import *
        >>> process = Process(process_name="Notepad++.exe")
        >>> value = process.read_float(0xCF6928)
        3.140625
        """

        buffer = ctypes.create_string_buffer(4)
        bytes_read = ctypes.c_size_t()
        ctypes.windll.kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(address), ctypes.byref(buffer), 4, ctypes.byref(bytes_read))
        return struct.unpack('<f', buffer.raw)[0]

    def read_double(self, address: int) -> float:
        """Читает 8 байтов по данному адресу.

        Read 8 bytes by given address.

        >>> from pymemoryapi import *
        >>> process = Process(process_name="Notepad++.exe")
        >>> value = process.read_double(0x80F288)
        10.5
        """

        buffer = ctypes.create_string_buffer(8)
        bytes_read = ctypes.c_size_t()
        ctypes.windll.kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(address), ctypes.byref(buffer), 8, ctypes.byref(bytes_read))
        return struct.unpack('<d', buffer.raw)[0]

    # Запись памяти
    def write_bytes(self, address: int, value: bytes) -> None:
        r"""Записывает данные байты по данному адресу.

        Write given length of bytes by given address.

        >>> from pymemoryapi import *
        >>> process = Process(process_name="Notepad++.exe")
        >>> process.write_bytes(0x3BB6490, b"\x00\x00\x00\x00\x00\x00\x39\x40")
        """

        address_to_write = ctypes.cast(address, ctypes.c_char_p)
        ctypes.windll.kernel32.WriteProcessMemory(self.handle, address_to_write, value, len(value), 0x0)

    def write_short(self, address: int, value: int) -> None:
        """Записывает 2 байта по данному адресу.

        Write 2 bytes by given address.

        >>> from pymemoryapi import *
        >>> process = Process(process_name="Notepad++.exe")
        >>> process.write_short(0x3BB6490, 1337)
        """

        address_to_write = ctypes.cast(address, ctypes.c_char_p)
        ctypes.windll.kernel32.WriteProcessMemory(self.handle, address_to_write, struct.pack('h', value), 2, 0x0)

    def write_ushort(self, address: int, value: int) -> None:
        """Записывает 2 байта по данному адресу.

        Write 2 bytes by given address.

        >>> from pymemoryapi import *
        >>> process = Process(process_name="Notepad++.exe")
        >>> process.write_ushort(0x3BB6490, 1337)
        """

        address_to_write = ctypes.cast(address, ctypes.c_char_p)
        ctypes.windll.kernel32.WriteProcessMemory(self.handle, address_to_write, struct.pack('H', value), 2, 0x0)

    def write_int(self, address: int, value: int) -> None:
        """Записывает 4 байта по данному адресу.

        Write 4 bytes by given address.

        >>> from pymemoryapi import *
        >>> process = Process(process_name="Notepad++.exe")
        >>> process.write_int(0x3BB6490, 1337)
        """

        address_to_write = ctypes.cast(address, ctypes.c_char_p)
        ctypes.windll.kernel32.WriteProcessMemory(self.handle, address_to_write, struct.pack('i', value), 4, 0x0)

    def write_uint(self, address: int, value: int) -> None:
        """Записывает 4 байта по данному адресу.

        Write 4 bytes by given address.

        >>> from pymemoryapi import *
        >>> process = Process(process_name="Notepad++.exe")
        >>> process.write_uint(0x3BB6490, 1337)
        """

        address_to_write = ctypes.cast(address, ctypes.c_char_p)
        ctypes.windll.kernel32.WriteProcessMemory(self.handle, address_to_write, struct.pack('I', value), 4, 0x0)

    def write_long(self, address: int, value: int) -> None:
        """Записывает 4 байта по данному адресу.

        Write 4 bytes by given address.

        >>> from pymemoryapi import *
        >>> process = Process(process_name="Notepad++.exe")
        >>> process.write_long(0x3BB6490, 1337)
        """

        address_to_write = ctypes.cast(address, ctypes.c_char_p)
        ctypes.windll.kernel32.WriteProcessMemory(self.handle, address_to_write, struct.pack('l', value), 4, 0x0)

    def write_ulong(self, address: int, value: int) -> None:
        """Записывает 4 байта по данному адресу.

        Write 4 bytes by given address.

        >>> from pymemoryapi import *
        >>> process = Process(process_name="Notepad++.exe")
        >>> process.write_ulong(0x3BB6490, 1337)
        """

        address_to_write = ctypes.cast(address, ctypes.c_char_p)
        ctypes.windll.kernel32.WriteProcessMemory(self.handle, address_to_write, struct.pack('L', value), 4, 0x0)

    def write_longlong(self, address: int, value: int) -> None:
        """Записывает 8 байтов по данному адресу.

        Write 8 bytes by given address.

        >>> from pymemoryapi import *
        >>> process = Process(process_name="Notepad++.exe")
        >>> process.write_longlong(0x3BB6490, 1337)
        """

        address_to_write = ctypes.cast(address, ctypes.c_char_p)
        ctypes.windll.kernel32.WriteProcessMemory(self.handle, address_to_write, struct.pack('q', value), 8, 0x0)

    def write_ulonglong(self, address: int, value: int) -> None:
        """Записывает 8 байтов по данному адресу.

        Write 8 bytes by given address.

        >>> from pymemoryapi import *
        >>> process = Process(process_name="Notepad++.exe")
        >>> process.write_ulonglong(0x3BB6490, 1337)
        """

        address_to_write = ctypes.cast(address, ctypes.c_char_p)
        ctypes.windll.kernel32.WriteProcessMemory(self.handle, address_to_write, struct.pack('Q', value), 8, 0x0)

    def write_float(self, address: int, value: float) -> None:
        """Записывает 4 байта по данному адресу.

        Write 4 bytes by given address.

        >>> from pymemoryapi import *
        >>> process = Process(process_name="Notepad++.exe")
        >>> process.write_float(0x3BB6490, 3.14)
        """

        address_to_write = ctypes.cast(address, ctypes.c_char_p)
        ctypes.windll.kernel32.WriteProcessMemory(self.handle, address_to_write, struct.pack('f', value), 4, 0x0)

    def write_double(self, address: int, value: float) -> None:
        """Записывает 8 байтов по данному адресу.

        Write 8 bytes by given address.

        >>> from pymemoryapi import *
        >>> process = Process(process_name="Notepad++.exe")
        >>> process.write_double(0x3BB6490, 3.14)
        """

        address_to_write = ctypes.cast(address, ctypes.c_char_p)
        ctypes.windll.kernel32.WriteProcessMemory(self.handle, address_to_write, struct.pack('d', value), 8, 0x0)
