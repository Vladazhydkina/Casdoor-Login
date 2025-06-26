#Casdoor Login + Binance WebSocket Crypto Tracker

Цей проєкт — це вебзастосунок, який реалізує:

-  Авторизацію через Casdoor за протоколом OpenID Connect
-  Збереження токена авторизації в HTTP-only cookie
-  Отримання живих даних про курс криптовалют із Binance WebSocket API
-  Доступ до WebSocket-даних **лише для авторизованих користувачів**
-  Сервер працює через HTTPS із TLS 1.2 на базі самопідписаного сертифіката `.p12`
-  Динамічне оновлення цін із візуальною індикацією росту/спаду 

---

## Стек технологій:

- **Node.js** + **Express** — бекенд-сервер
- **Casdoor** — Identity & Access Management (IAM)
- **OpenID Connect** — протокол авторизації
- **JWT** — обробка токена авторизації
- **WebSocket** — підключення до Binance API
- **Binance WebSocket API** — поточні ціни монет
- **HTTPS** — сервер із TLS-сертифікатом (`.p12`)
- **Docker** — для контейнеризації
