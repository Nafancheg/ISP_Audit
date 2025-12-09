# Аудит .md файлов репозитория

**Дата:** 09.12.2025  
**Было файлов:** 79  
**Осталось:** 36 активных + 23 в архиве

---

## ✅ Результат очистки

| Категория | До | После |
|-----------|-----|-------|
| Корневые | 7 | 4 |
| docs/ | 16 | 5 |
| agents/ (активные) | 21 | 15 |
| agents/archive_runs/ | 0 | 23 |
| Шаблоны (_template/) | 11 | 11 |
| native/publish/TestNetworkApp | 3 | 3 |
| **ИТОГО активных** | **79** | **36** |

---

## 🟢 Актуальные файлы (36)

| Файл | Причина удаления |
|------|------------------|
| `ARCHITECTURE_V2.md` | Устарел, заменён на `ARCHITECTURE_CURRENT.md` (дата 27.11.2025) |
| `docs/isp_audit_analysis.md` | Дублирует `docs/analysis_star_citizen.md` |
| `docs/star_citizen_audit_plan.md` | Устаревший план, уже реализован |
| `project_file_map.md` | Заменён на `docs/full_repo_audit_v2.md` |
| `agents/research_agent/code_first_audit.md` | Черновик, финальный есть |
| `agents/research_agent/code_first_audit_final.md` | Заменён на `code_first_audit_final_v2.md` |
| `agents/research_agent/deep_audit_findings.md` | Черновик |
| `agents/research_agent/findings.md` | Устарел (ноябрь 2025), заменён на `findings_2025_12_01.md` |
| `agents/qa_agent/test_report.md` | Заменён на `test_report_v2.md` |

### 🟡 УДАЛИТЬ (устаревшие планы/todo)

| Файл | Причина |
|------|---------|
| `todo_detect.md` | Детальный TODO по детекции — информация дублируется в `docs/TODO.md` |
| `docs/bypass_strategy_todo.md` | Устаревший TODO, частично реализован |
| `docs/e2e_test_checklist.md` | Чеклист для старой exe-архитектуры, не актуален |
| `docs/exe_scenario_architecture.md` | DESIGN статус, никогда не реализован |
| `docs/empty_sniff_diagnostics.md` | Диагностика проблем снифа — интегрировано в код |
| `docs/fshud_live_testing_plan.md` | Специфичный план тестирования FsHud — устарел |
| `docs/live_testing_status.md` | Статус реализации — уже всё реализовано |
| `docs/traffic_capture_hybrid_approach.md` | Концепт multi-layer — реализовано |
| `docs/ui_migration_options.md` | Планы миграции UI на веб — не актуально |
| `agents/planning_agent/plan_archive_profiles.md` | Архивный план |
| `agents/planning_agent/plan_full.md` | Старый план |

### 🟢 ОСТАВИТЬ (актуальные)

| Файл | Назначение |
|------|------------|
| `README.md` | Основная документация пользователя |
| `CHANGELOG.md` | История изменений |
| `CLAUDE.md` | Инструкции для AI-ассистентов |
| `.github/copilot-instructions.md` | Инструкции для Copilot |
| `ARCHITECTURE_CURRENT.md` | **Главный архитектурный документ** |
| `docs/TODO.md` | Единый список задач |
| `docs/full_repo_audit_v2.md` | Полный аудит репозитория |
| `docs/analysis_star_citizen.md` | Анализ требований Star Citizen |
| `docs/bypass_architecture_deep_dive.md` | Глубокое исследование bypass |
| `native/README.md` | Документация WinDivert |
| `publish/README.md` | Инструкции по публикации |
| `agents/README.md` | Документация agent workflow |
| `agents/WORKFLOW.md` | Описание процесса работы агентов |
| `agents/task_owner/current_task.md` | Текущая задача (рабочий файл) |
| `agents/task_owner/TASK_TEMPLATE.md` | Шаблон задачи |
| `agents/planning_agent/plan.md` | Текущий план |
| `agents/planning_agent/README.md` | Документация планировщика |
| `agents/research_agent/findings_2025_12_01.md` | Последние findings |
| `agents/research_agent/code_first_audit_final_v2.md` | Финальный аудит |
| `agents/research_agent/deep_audit_report_final.md` | Финальный отчёт |
| `agents/qa_agent/test_report_v2.md` | Актуальный отчёт тестирования |
| `agents/qa_agent/improvements_discussed.md` | Обсуждаемые улучшения |
| `agents/delivery_agent/changelog.md` | Changelog деливери |
| `TestNetworkApp/README.md` | Документация тестового приложения |

### ⚪ АРХИВИРОВАТЬ (agents/runs/*)

Вся папка `agents/runs/` содержит **историю выполненных задач** (3 запуска):
- `20251029-120854-vpn-tests-fail/` — 11 файлов
- `20251029-123529-playable-verdict/` — 11 файлов
- `20251030-171114-arch-fix/` — 1 файл

**Рекомендация:** Переместить в `agents/archive/` или удалить полностью (история есть в git).

### ⚪ ШАБЛОНЫ (agents/_template/*)

11 файлов шаблонов — **оставить как есть**.

---

## Итого действий

| Действие | Количество файлов |
|----------|-------------------|
| 🔴 Удалить немедленно | 9 |
| 🟡 Удалить (устаревшие планы) | 11 |
| 🟢 Оставить | 26 |
| ⚪ Архивировать runs/ | 23 |
| ⚪ Шаблоны | 11 |
| **ИТОГО** | **79** |

---

## Команда для очистки

```powershell
# 1. Удалить устаревшие файлы
$toDelete = @(
    "ARCHITECTURE_V2.md",
    "project_file_map.md",
    "todo_detect.md",
    "docs/isp_audit_analysis.md",
    "docs/star_citizen_audit_plan.md",
    "docs/bypass_strategy_todo.md",
    "docs/e2e_test_checklist.md",
    "docs/exe_scenario_architecture.md",
    "docs/empty_sniff_diagnostics.md",
    "docs/fshud_live_testing_plan.md",
    "docs/live_testing_status.md",
    "docs/traffic_capture_hybrid_approach.md",
    "docs/ui_migration_options.md",
    "agents/research_agent/code_first_audit.md",
    "agents/research_agent/code_first_audit_final.md",
    "agents/research_agent/deep_audit_findings.md",
    "agents/research_agent/findings.md",
    "agents/qa_agent/test_report.md",
    "agents/planning_agent/plan_archive_profiles.md",
    "agents/planning_agent/plan_full.md"
)

# 2. Архивировать runs/
Move-Item "agents/runs" "agents/archive_runs"

# 3. Git commit
git add -A
git commit -m "Очистка устаревшей документации (20 файлов)"
```
