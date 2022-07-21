# pymemoryapi
Простая быстрая библиотека для работы с оперативной памятью процесса.
---
### Требования
Python ^3.8 <br />
ОС: Windows 7, 8, 9, 10 и 11 (x64)

### Примеры
Подключение к процессу и получение информации о нем.
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

# Вывод:
# ---------------
# handle: 1356
# name: Terraria.exe
# pid: 23696

# handle: 1840
# name: Discord.exe
# pid: 11064
```
