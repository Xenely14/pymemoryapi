# pymemoryapi
Простая быстрая библиотека для работы с оперативной памятью процесса.

### Примечание
Библиотека содержит самые базовые и необходимые для работы с память функции и классы, такие как: чтение и запись памяти, сканер паттернов, получение информации о модулях процесса и трамплин хуки. Библиотека не имеет внешних зависимостей, для её подключения достаточно стандарных модулей Python, работает сильно быстрее Pymem.

### Требования
Python ^3.8 <br />
ОС: Windows 7, 8, 10 и 11 (x64)

### Установка
```python
pip install pymemoryapi
```

### Примеры
Подключение к процессу и получение информации о нем
```python
import pymemoryapi

terraria_process = pymemoryapi.Process(process_name="Terraria.exe")
print(f"handle: {terraria_process.handle}")
print(f"name: {terraria_process.name}")
print(f"pid: {terraria_process.pid}\n")

discord_process = pymemoryapi.Process(pid=11064)
print(f"handle: {discord_process.handle}")
print(f"name: {discord_process.name}")
print(f"pid: {discord_process.pid}")

```
![Alt Image](https://media.discordapp.net/attachments/770327730570133524/999818711030562976/unknown.png)

Чтение и запись памяти процесса
```python
import pymemoryapi

process = pymemoryapi.Process(process_name="notepad++.exe")

some_address = 0x06B7D5A8
print(f"address value: {process.read_float(some_address)}")
process.write_float(some_address, 1337.228)
print(f"new address value: {process.read_float(some_address)}")

```
![Alt Image](https://cdn.discordapp.com/attachments/770327730570133524/999824405347713034/unknown.png)
![Alt Image](https://media.discordapp.net/attachments/770327730570133524/999824443176124456/unknown.png)

![Alt Image](https://media.discordapp.net/attachments/770327730570133524/999825134632304680/unknown.png)

Сканер паттернов
```python
from time import time
import pymemoryapi

process = pymemoryapi.Process(process_name="notepad++.exe")

# ?? - случайный байт
# Если нужно вернуть первый попавшийся адрес можно передать доп. аргумент - return_first_found = True
# метод raw_patter_scan(start_address, end_address, pattern) делает тоже самое, только работает с rb'байты', а не с b'байты'
start_time = time()
addresses = process.pattern_scan(0, 0x100000000, "00 00 A0 ?? 80 EF")
stop_time = time()

for address in addresses:
    print('found address:', hex(address))

print(f'pattern scan time: {start_time - start_time} sec.')

```
![Alt Image](https://cdn.discordapp.com/attachments/770327730570133524/999831073750003753/unknown.png)
![Alt Image](https://cdn.discordapp.com/attachments/770327730570133524/999831231808143450/unknown.png)

Получение информации о модулях процесса
```python
import pymemoryapi

process = pymemoryapi.Process(process_name="notepad++.exe")
kernel_module = process.get_module_info("KERNEL32.dll")

print(f"KERNEL32.dll BaseAddress: {hex(kernel_module.BaseAddress)}")
print(f"KERNEL32.dll SizeOfImage: {hex(kernel_module.SizeOfImage)}")
print(f"KERNEL32.dll EntryPoint: {hex(kernel_module.EntryPoint)}")

```
![Alt Image](https://cdn.discordapp.com/attachments/770327730570133524/999823378401738772/unknown.png)

Трамплин хуки
```python
# Бесконечные хп в Terraria

import pymemoryapi

process = pymemoryapi.Process(process_name="Terraria.exe")

# Ищем инструкцию, которая записывает значение хп в цикле -> fild dword ptr [esi + 000003E4]
health_instruction = process.raw_pattern_scan(0, 0xF0000000, "DB 86 E4 03 00 00 D9 5D F8 D9 45 F8", return_first_found=True)

# Устанавливаем трамплин хук на инструкцию, длина инструкции - не менее 7 байтов с use_x64_registers=False, не менее 12 с use_x64_registers=True
# mov eax, <address>
# jmp eax
# use_x64_registers = False - использование eax (представлено выше) для хранения адреса аллока, use_x64_registers = True - использование rax
# Если игра не умеет обращаться с rax регисторм - используйте use_x64_registers = False
health_hook = pymemoryapi.TrampolineHook(process, health_instruction, 18, 4096, use_x64_registers=False)

# C7 86 E4 03 00 00 39 05 00 00 -> mov [esi + 000003E4], (int)1337
# Для перевода байтов в строчный паттерн можно использовать метод pymemoryapi.heximate_bytes(bytes)
health_hook.insert_bytecode("C7 86 E4 03 00 00 39 05 00 00")

```
![Alt Image](https://media.discordapp.net/attachments/770327730570133524/1000012062447120414/before_hook.png)
![Alt Image](https://media.discordapp.net/attachments/770327730570133524/1000011528830992465/after_hook.png?width=1440&height=339)
![Alt Image](https://media.discordapp.net/attachments/770327730570133524/1000012151727067156/hook.png)

Прочие функции
```python
import pymemoryapi

process = pymemoryapi.Process("notepad++.exe")

print(pymemoryapi.list_processes_ids())
# [0, 2560, ..., 11276]
print(pymemoryapi.list_processes_names())
# ['opera.exe', 'NVIDIA Share.exe', ...,  'Code.exe']
print(pymemoryapi.list_processes())
# [('opera.exe', 8704), ('NVIDIA Share.exe', 15880), ..., ('Code.exe', 18988)]
print(pymemoryapi.list_modules(process.handle))
# ['notepad++.exe', 'WINTRUST.dll', ..., 'ntdll.dll']

print(pymemoryapi.heximate_bytes(pymemoryapi.mov_difference(0x02280016 - 0x27C52878)))
# 9E D7 62 DA
print(pymemoryapi.is_64_bit(process.handle))
# True
print(pymemoryapi.table_memory(process, 0x017995DC, 8, 36))
# 17995DC | 55 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
# 1799600 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 EA DA 3E 84 41 EA 00 08 80 A5 84 CF
# 1799624 | 80 A5 F4 CF 80 A5 54 CE 80 A5 24 CE 80 A5 E4 CF 50 D0 B4 18 50 D0 B4 18 50 D0 B4 18 50 D0 B4 18 50 D0 B4 18
# 1799648 | 50 D0 B4 18 50 D0 B4 18 50 D0 B4 18 50 D0 B4 18 50 D0 B4 18 50 D0 B4 18 50 D0 B4 18 50 D0 B4 18 50 D0 B4 18
# 179966C | 50 D0 B4 18 50 D0 B4 18 50 D0 B4 18 50 D0 B4 18 50 D0 B4 18 50 D0 B4 18 50 D0 B4 18 50 D0 B4 18 50 D0 B4 18
# 1799690 | 50 D0 B4 18 50 D0 B4 18 50 D0 B4 18 50 D0 B4 18 DC DA 3E B2 5F EA 00 08 41 63 4D 67 03 00 00 00 00 00 00 00
# 17996B4 | 5C 00 57 00 49 00 4E 00 00 00 AC 01 60 D6 15 76 00 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
# 17996D8 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

print(hex(pymemoryapi.virtual_alloc_ex(process.handle, 4096)))
# 0x15d0000
memory_info = pymemoryapi.virtual_query_ex(process.handle, 0x15d0000)
# Возвращает структуру
# class MEMORY_BASIC_INFORMATION(ctypes.Structure):

#     _fields_ = [
#         ("BaseAddress", ctypes.c_ulonglong),
#         ("AllocationBase", ctypes.c_ulonglong),
#         ("AllocationProtect", ctypes.c_ulong),
#         ("align1", ctypes.c_ulong),
#         ("RegionSize", ctypes.c_ulonglong),
#         ("State", ctypes.c_ulong),
#         ("Protect", ctypes.c_ulong),
#         ("Type", ctypes.c_ulong),
#         ("align2", ctypes.c_ulong),
#     ]
print(hex(memory_info.BaseAddress))
print(memory_info.RegionSize)
# 0x15d0000
# 4096

```
### Сравнение производительности с Pymem
```python
import pymemoryapi
import pymem
import time

pymemoryapi_process = pymemoryapi.Process(process_name="Notepad++.exe")
pymem_process = pymem.Pymem("Notepad++.exe")

address = 0x06F667DC

# Чтение (3кк итераций)
start = time.time()
for _ in range(3000000):
    pymemoryapi_process.read_float(address)
stop = time.time()
print(f'pymemoryapi reading: {stop - start} sec')

start = time.time()
for _ in range(3000000):
    pymem_process.read_float(address)
stop = time.time()
print(f'pymem reading: {stop - start} sec\n')

# Запись (100к итераций)
start = time.time()
for _ in range(100000):
    pymemoryapi_process.write_float(address, 20.0)
stop = time.time()
print(f'pymemoryapi writing: {stop - start} sec')

start = time.time()
for _ in range(100000):
    pymem_process.write_float(address, 20.0)
stop = time.time()
print(f'pymem writing: {stop - start} sec\n')

# Сканер паттернов
start = time.time()
pymemoryapi_process.pattern_scan(0, 0x90000000, "00 00 A0 41 00 00 00 00 D5 FF")
stop = time.time()
print(f'pymemoryapi pattern scanning: {stop - start} sec')

start = time.time()
scan_region = 0
while scan_region < 0x90000000:
    scan_region, founded_addresses = pymem.pattern.scan_pattern_page(pymem_process.process_handle, scan_region, b'\x00\x00\xA0\x41\x00\x00\x00\x00\xd5\xff')
stop = time.time()
print(f'pymem pattern scanning: {stop - start} sec')

```
![Alt Image](https://media.discordapp.net/attachments/770327730570133524/1000025656211537970/unknown.png)
