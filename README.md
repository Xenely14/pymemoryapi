# pymemoryapi
Простая быстрая библиотека для работы с оперативной памятью процесса.

### Примечание
Библиотека содержит самые базоыве и нообходимые для работы с память функции и классы, такие как: чтение и запись памяти, сканер паттернов, получение информации о модулях процесса и трамплин хуки. Библиотека не имеет внешних зависимостей, для её подключения достаточно стандарных модулей Python, работает сильно быстрее Pymem.

### Требования
Python ^3.8 <br />
ОС: Windows 7, 8, 9, 10 и 11 (x64)

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
