# isp_audit_native (Rust cdylib)

Цель: подготовить нативную Rust DLL (`isp_audit_native.dll`), которая **проксирует** вызовы в `WinDivert.dll` через C ABI.

Важно: это **заготовка** для бесшовного переключения P/Invoke в будущем. Текущий .NET код проекта не меняется.

## Что внутри

- `src/lib.rs` экспортирует функции `divert_*` с calling convention `system` (совместимо с `CallingConvention.Winapi`).
- DLL динамически грузит `WinDivert.dll` (`LoadLibraryA`) и вызывает нужные экспорты через `GetProcAddress`.
- Структура адреса (`DivertAddress`) сделана строго размером **80 байт** (8 + 4 + 4 + 64), совместимо с `WinDivertNative.Address`.

## Сборка

Требования: установлен Rust toolchain (MSVC).

```powershell
cd native\isp_audit_native
cargo build --release
```

Результат:
- `native/isp_audit_native/target/release/isp_audit_native.dll`

## Дальше (план переключения)

Позже добавится альтернативный C# interop-класс (например, `WinDivertNativeRust.cs`) c `DllImport("isp_audit_native.dll")` и feature-flag для выбора между `WinDivert.dll` и `isp_audit_native.dll`.
