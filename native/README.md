# WinDivert Native Libraries

Для работы **Exe-сценария** (анализ трафика и автоматический обход блокировок) требуется **WinDivert 2.2+** для Windows 10/11 x64.

## Установка

1. **Скачайте WinDivert 2.2+** с официального сайта:
   - https://www.reqrypt.org/windivert.html
   - Или GitHub Releases: https://github.com/basil00/Divert/releases

2. **Распакуйте архив** (например, `WinDivert-2.2.2-A.zip`)

3. **Скопируйте файлы x64** в эту директорию (`native/`):
   ```
   WinDivert-2.2.2-A/
   ├── x64/
   │   ├── WinDivert.dll      → скопировать сюда
   │   └── WinDivert64.sys    → скопировать сюда
   ```

4. **Структура должна быть:**
   ```
   ISP_Audit/
   ├── native/
   │   ├── WinDivert.dll      ✓ (x64)
   │   ├── WinDivert64.sys    ✓ (x64)
   │   └── README.md          (этот файл)
   ```

5. **Пересоберите проект:**
   ```powershell
   dotnet build -c Debug
   ```
   
   DLL и SYS файлы будут автоматически скопированы в `bin/Debug/net9.0-windows/`

## Требования

- **Windows 10/11 x64** (WinDivert не поддерживает Windows 7/8)
- **Права администратора** (для загрузки драйвера WinDivert64.sys)
- **WinDivert 2.2+** (для SOCKET layer поддержки с ProcessId фильтром)

## Проверка установки

После сборки убедитесь что файлы скопировались:

```powershell
ls bin\Debug\net9.0-windows\WinDivert*
```

Должны быть:
- `WinDivert.dll` (~60 KB)
- `WinDivert64.sys` (~40 KB)

## Troubleshooting

**Ошибка:** `Unable to load DLL 'WinDivert.dll' or one of its dependencies: Не найден указанный модуль. (0x8007007E)`

**Причина:** WinDivert.dll отсутствует в директории с exe-файлом.

**Решение:** 
1. Проверьте что файлы скопированы в `native/`
2. Пересоберите проект: `dotnet build -c Debug`
3. Убедитесь что в `bin/Debug/net9.0-windows/` есть `WinDivert.dll`

---

**Примечание:** WinDivert является open-source проектом под лицензией LGPL v3. При распространении ISP_Audit нужно включать WinDivert.dll и WinDivert64.sys в пакет или указать ссылку на загрузку.
