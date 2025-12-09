# Реализация — сводный вердикт и советы

Дата: 2025-10-29 | ID: 20251029-123529-playable-verdict

## Изменения (код)
- `Output/ReportWriter.cs`
  - Добавлено `Summary.playable` и расчёт вердикта (YES/NO/MAYBE/UNKNOWN).
  - Вывод `PLAYABLE` в `BuildHumanText`.
  - В `BuildAdviceText` добавлен верхний блок «Вердикт: …».
- GUI (план): заменить статическую фразу про VPN на динамическую рекомендацию.
  - Технически: собрать строку из `summary` (DNS/TLS/TCP) и отобразить в баннере.

## Статус
- Вердикт реализован и попадает в JSON/консоль.
- Для GUI добавлены вспомогательные функции (BuildUiWarnings/BuildUiRecommendation) — их можно использовать при следующей правке `MainWindow.xaml.cs`.
