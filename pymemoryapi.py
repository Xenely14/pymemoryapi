from ctypes.wintypes import *
from typing import Any
import struct
import ctypes
import locale
import os
import re

# WinAPI флаги
PROCESS_ALL_ACCESS = 0x001F0FFF
PROCESS_VM_OPERATION = 0x0008
LIST_MODULES_ALL = 0x003
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020

MEM_COMMIT = 0x00001000

PAGE_EXECUTE_READ = 0x0020
PAGE_EXECUTE_READWRITE = 0x0040
PAGE_READONLY = 0x2
PAGE_READWRITE = 0x4


MAX_PATH = 260

# WinAPI обозначения типов
ctypes.windll.kernel32.OpenProcess.restype = HANDLE
ctypes.windll.kernel32.VirtualAllocEx.restype = LPVOID


def heximate_bytes(bytearray: bytes) -> str:
    """Возвращает массив байтов в ввиде строчного паттерна."""

    heximate_bytes = bytearray.hex()
    return (" ".join([heximate_bytes[i: i + 2] for i in range(0, len(heximate_bytes), 2)])).strip().upper()


def mov_difference(offset: int) -> bytes:
    """Возвращает ассемблерное представление mov оффсета."""

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
    """Возвращает список ID всех активных процессов."""

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
    """Возвращает список имен всех активных процессов."""

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
    """Возвращает список ID и имен всех активных процессов."""

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


def is_64_bit(process_handle: int) -> bool:
    """Проверяет является ли процесс 64-битным."""

    wow_64 = ctypes.c_long()
    ctypes.windll.kernel32.IsWow64Process(process_handle, ctypes.byref(wow_64))
    return bool(wow_64)


def table_memory(process: object, address: int, rows: int, row_length: int = 24) -> None:
    """Строит таблицу как в Cheat Engine по заданому адресу."""

    try:
        for i in range(rows):
            row_bytes = process.read_bytes(address + (i * row_length), row_length)
            print(hex(address + (i * row_length))[2:len(hex(address + (i * row_length)))].upper() + ' | ' + heximate_bytes(row_bytes))
    except Exception:
        MemoryAPIException("Невозможно построить таблицу по заданому адресу.")


def list_modules(process_handle: int) -> list:
    """Возвращает список всех подключенных модулей к процессу."""

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
    """Выделяет указаное количество байт в памяти процесса."""

    allocation_address = ctypes.windll.kernel32.VirtualAllocEx(process_handle, 0, bytes_length, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    if not allocation_address:
        raise MemoryAPIException("Handle процесса передан неверно, или размер буфера некорректен.")
    else:
        return allocation_address


def virtual_query_ex(process_handle: int, address: int) -> object:
    """Возвращает объект MEMORY_BASIC_INFORMATION, содержащий информацию о регионе памяти по адресу."""

    memory_information = MEMORY_BASIC_INFORMATION()
    ctypes.windll.kernel32.VirtualQueryEx(process_handle, ctypes.cast(address, ctypes.c_char_p), ctypes.byref(memory_information), ctypes.sizeof(memory_information))
    return memory_information


class MemoryAPIException(Exception):
    """Базовый класс ошибок MemoryAPI."""
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
        ctypes.windll.psapi.psapi.GetModuleFileNameExA(self.process_handle, ctypes.c_void_p(self.BaseAddress), _filename, ctypes.sizeof(_filename))
        return _filename.value.decode(locale.getpreferredencoding())


class TrampolineHook:
    """Класс cодержащий методы, необходимые для создание хуков."""

    def unhook(self) -> None:
        """Убирает хук и удаляет объект."""

        self.__process.write_bytes(self.__instruction_address, self.original_code)

    def clear(self) -> None:
        """Очищает байткод, оставляя только оригинальный код."""

        self.hook_bytecode = self.original_code + self.__backward__jump
        while len(self.hook_bytecode) != self.__alloc_buffer_size:
            self.hook_bytecode += b'\x00'
        else:
            self.__process.write_bytes(self.__instruction_address, self.hook_bytecode)

    def insert_bytecode(self, bytecode: str) -> None:
        """Подставляет данный байткод перед оригинальным кодом."""
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
    """Базовый класс MemoryAPI. Содержит методы, необходимые для работы с ОЗУ процесса."""

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
        """Возвращает объект MODULE, содержащий информацию о модуле."""

        hModules = (ctypes.c_void_p * 1024)()
        process_module_success = ctypes.windll.psapi.EnumProcessModulesEx(self.handle, ctypes.byref(hModules), ctypes.sizeof(hModules), ctypes.byref(ctypes.c_ulong()), LIST_MODULES_ALL)
        if process_module_success:
            hModules = iter(i for i in hModules if i)
            for hModule in hModules:
                module_info = MODULE(self.handle)
                ctypes.windll.psapi.GetModuleInformation(self.handle, ctypes.c_void_p(hModule), ctypes.byref(module_info), ctypes.sizeof(module_info))
                if module_name.lower() == module_info.name.lower():
                    return module_info

    # Сканер сигнатур
    def pattern_scan(self, start_address: int, end_address: int, pattern: str, return_first_found: bool = False) -> Any:
        """Ищет адреса с заданными байтам в заданном диапазоне."""

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
        """Ищет адреса с заданными байтам в заданном диапазоне."""

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
        """Читает заданое количество байт по данному адресу."""

        buffer = ctypes.create_string_buffer(length)
        bytes_read = ctypes.c_size_t()
        ctypes.windll.kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(address), ctypes.byref(buffer), length, ctypes.byref(bytes_read))
        return buffer.raw

    def read_short(self, address: int) -> int:
        """Читает 2 байта по данному адресу."""

        buffer = ctypes.create_string_buffer(2)
        bytes_read = ctypes.c_size_t()
        ctypes.windll.kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(address), ctypes.byref(buffer), 2, ctypes.byref(bytes_read))
        return struct.unpack('<h', buffer.raw)[0]

    def read_ushort(self, address: int) -> int:
        """Читает 2 байта по данному адресу."""

        buffer = ctypes.create_string_buffer(2)
        bytes_read = ctypes.c_size_t()
        ctypes.windll.kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(address), ctypes.byref(buffer), 2, ctypes.byref(bytes_read))
        return struct.unpack('<H', buffer.raw)[0]

    def read_int(self, address: int) -> int:
        """Читает 4 байта по данному адресу."""

        buffer = ctypes.create_string_buffer(4)
        bytes_read = ctypes.c_size_t()
        ctypes.windll.kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(address), ctypes.byref(buffer), 4, ctypes.byref(bytes_read))
        return struct.unpack('<i', buffer.raw)[0]

    def read_uint(self, address: int) -> int:
        """Читает 4 байта по данному адресу."""

        buffer = ctypes.create_string_buffer(4)
        bytes_read = ctypes.c_size_t()
        ctypes.windll.kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(address), ctypes.byref(buffer), 4, ctypes.byref(bytes_read))
        return struct.unpack('<I', buffer.raw)[0]

    def read_long(self, address: int) -> int:
        """Читает 4 байта по данному адресу."""

        buffer = ctypes.create_string_buffer(4)
        bytes_read = ctypes.c_size_t()
        ctypes.windll.kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(address), ctypes.byref(buffer), 4, ctypes.byref(bytes_read))
        return struct.unpack('<l', buffer.raw)[0]

    def read_ulong(self, address: int) -> int:
        """Читает 4 байта по данному адресу."""

        buffer = ctypes.create_string_buffer(4)
        bytes_read = ctypes.c_size_t()
        ctypes.windll.kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(address), ctypes.byref(buffer), 4, ctypes.byref(bytes_read))
        return struct.unpack('<L', buffer.raw)[0]

    def read_longlong(self, address: int) -> int:
        """Читает 8 байтов по данному адресу."""

        buffer = ctypes.create_string_buffer(8)
        bytes_read = ctypes.c_size_t()
        ctypes.windll.kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(address), ctypes.byref(buffer), 8, ctypes.byref(bytes_read))
        return struct.unpack('<q', buffer.raw)[0]

    def read_ulonglong(self, address: int) -> int:
        """Читает 8 байтов по данному адресу."""

        buffer = ctypes.create_string_buffer(8)
        bytes_read = ctypes.c_size_t()
        ctypes.windll.kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(address), ctypes.byref(buffer), 8, ctypes.byref(bytes_read))
        return struct.unpack('<Q', buffer.raw)[0]

    def read_float(self, address: int) -> float:
        """Читает 4 байта по данному адресу."""

        buffer = ctypes.create_string_buffer(4)
        bytes_read = ctypes.c_size_t()
        ctypes.windll.kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(address), ctypes.byref(buffer), 4, ctypes.byref(bytes_read))
        return struct.unpack('<f', buffer.raw)[0]

    def read_double(self, address: int) -> float:
        """Читает 8 байтов по данному адресу."""

        buffer = ctypes.create_string_buffer(8)
        bytes_read = ctypes.c_size_t()
        ctypes.windll.kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(address), ctypes.byref(buffer), 8, ctypes.byref(bytes_read))
        return struct.unpack('<d', buffer.raw)[0]

    # Запись памяти
    def write_bytes(self, address: int, value: bytes) -> None:
        """Записывает данные байты по данному адресу."""

        address_to_write = ctypes.cast(address, ctypes.c_char_p)
        ctypes.windll.kernel32.WriteProcessMemory(self.handle, address_to_write, value, len(value), 0x0)

    def write_short(self, address: int, value: int) -> None:
        """Записывает 2 байта по данному адресу."""

        address_to_write = ctypes.cast(address, ctypes.c_char_p)
        ctypes.windll.kernel32.WriteProcessMemory(self.handle, address_to_write, struct.pack('h', value), 2, 0x0)

    def write_ushort(self, address: int, value: int) -> None:
        """Записывает 2 байта по данному адресу."""

        address_to_write = ctypes.cast(address, ctypes.c_char_p)
        ctypes.windll.kernel32.WriteProcessMemory(self.handle, address_to_write, struct.pack('H', value), 2, 0x0)

    def write_int(self, address: int, value: int) -> None:
        """Записывает 4 байта по данному адресу."""

        address_to_write = ctypes.cast(address, ctypes.c_char_p)
        ctypes.windll.kernel32.WriteProcessMemory(self.handle, address_to_write, struct.pack('i', value), 4, 0x0)

    def write_uint(self, address: int, value: int) -> None:
        """Записывает 4 байта по данному адресу."""

        address_to_write = ctypes.cast(address, ctypes.c_char_p)
        ctypes.windll.kernel32.WriteProcessMemory(self.handle, address_to_write, struct.pack('I', value), 4, 0x0)

    def write_long(self, address: int, value: int) -> None:
        """Записывает 4 байта по данному адресу."""

        address_to_write = ctypes.cast(address, ctypes.c_char_p)
        ctypes.windll.kernel32.WriteProcessMemory(self.handle, address_to_write, struct.pack('l', value), 4, 0x0)

    def write_ulong(self, address: int, value: int) -> None:
        """Записывает 4 байта по данному адресу."""

        address_to_write = ctypes.cast(address, ctypes.c_char_p)
        ctypes.windll.kernel32.WriteProcessMemory(self.handle, address_to_write, struct.pack('L', value), 4, 0x0)

    def write_longlong(self, address: int, value: int) -> None:
        """Записывает 8 байтов по данному адресу."""

        address_to_write = ctypes.cast(address, ctypes.c_char_p)
        ctypes.windll.kernel32.WriteProcessMemory(self.handle, address_to_write, struct.pack('q', value), 8, 0x0)

    def write_ulonglong(self, address: int, value: int) -> None:
        """Записывает 8 байтов по данному адресу."""

        address_to_write = ctypes.cast(address, ctypes.c_char_p)
        ctypes.windll.kernel32.WriteProcessMemory(self.handle, address_to_write, struct.pack('Q', value), 8, 0x0)

    def write_float(self, address: int, value: float) -> None:
        """Записывает 4 байта по данному адресу."""

        address_to_write = ctypes.cast(address, ctypes.c_char_p)
        ctypes.windll.kernel32.WriteProcessMemory(self.handle, address_to_write, struct.pack('f', value), 4, 0x0)

    def write_double(self, address: int, value: float) -> None:
        """Записывает 8 байтов по данному адресу."""

        address_to_write = ctypes.cast(address, ctypes.c_char_p)
        ctypes.windll.kernel32.WriteProcessMemory(self.handle, address_to_write, struct.pack('d', value), 8, 0x0)
