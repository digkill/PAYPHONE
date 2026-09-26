# AgentDevelop — PAYPHONE

Рабочая копия агентского контекста этого продукта. Канон структуры: `Projects/Composer/schema/agentdevelop.md`.
Данные синкаются в PostgreSQL Composer (`slug: payphone`).

## С чего начать

1. **Портфолио** — [`portfolio/INDEX.md`](portfolio/INDEX.md) и [`portfolio/screenshots/`](portfolio/screenshots/).
2. Документация — [`documentation/INDEX.md`](documentation/INDEX.md).
3. Статья о разработке — [`article/INDEX.md`](article/INDEX.md).
4. По задаче открой один файл: `memory/`, `features/`, `pains/`, `problems/`, `tasks/`, `prs/`, `context/`.

## Правила

- Код побеждает устаревший markdown. Поправил инвариант — обнови память в том же изменении.
- Не класть секреты, ключи, `.env`, токены.
- После правок: `POST http://127.0.0.1:18080/v1/sync` или рестарт Composer API.
