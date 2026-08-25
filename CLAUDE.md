## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).

## Обязательно после каждого изменения кода

Три шага, ни один не пропускается — даже для правки в одну строку:

1. **Граф** — `graphify update .` (AST-разбор, без обращений к API).
2. **Документация везде.** Их две, и они расходятся независимо:
   - `readme.md` — поля `servers.json`, переменные `.env`, структура файлов,
     разделы карточки сервера, разбор типичных ошибок;
   - `HELP_SECTIONS` в `bot/config_editor.py` — справка внутри бота
     (⚙️ Настройка → 📖 Справка). Каждый раздел обязан умещаться в одно
     сообщение Telegram, это проверяется тестом.
   - `config/example.servers.json` — если добавилось поле конфига. Только
     обезличенные данные: репозиторий публичный.
3. **Тесты** — `pytest`. Новое поведение покрывается тестом, найденная
   ошибка — тестом на регрессию.

Проверять сверкой по коду, а не по памяти: пройтись `grep` по именам новых
полей и разделов и убедиться, что они встречаются и в `readme.md`, и в
справке бота. Пробелы находились именно так.

## Безопасность репозитория

Репозиторий публичный (github.com/iamrlufe/telegramBot). В коммит не должны
попадать реальные хосты, домены, IP, имена ВМ и учётные записи — ни в
примерах, ни в тестовых фикстурах, ни в комментариях. Для документации:
адреса из `192.0.2.0/24`, домен `example.local`.
