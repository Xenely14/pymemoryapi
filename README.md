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

```
![Alt Image](https://media.discordapp.net/attachments/770327730570133524/999818711030562976/unknown.png)
