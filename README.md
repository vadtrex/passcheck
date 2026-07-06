# PassCheck

Small Express.js microservice for evaluating password strength in regulated environments. It scores passwords with [zxcvbn](https://github.com/zxcvbn-ts/zxcvbn), checks them against [Have I Been Pwned](https://haveibeenpwned.com/) using k-anonymity (only the first five SHA-1 hash characters leave the server), and returns a structured verdict with strength, breach status, and actionable feedback. The API follows NIST SP 800-63B rules - no forced composition requirements, breached passwords are always rejected, and optional username/email context helps detect personal information in passphrases. Stateless, container-ready, and intended to run as an internal service behind auth layer.

## Quick start

```bash
git clone https://github.com/vadtrex/passcheck.git
cd passcheck
docker build -t passcheck .
docker run --rm -p 3000:3000 passcheck
```

Verify the service is up:

```bash
curl http://localhost:3000/healthz
```

Evaluate a password:

```bash
curl -X POST http://localhost:3000/v1/password/evaluate \
  -H "Content-Type: application/json" \
  -d "{\"password\":\"Panoramic-BlueOrbit-9341-walnut-vivid!\"}"
```

## API

OpenAPI 3.1 specification: [`openapi.yaml`](openapi.yaml).

### `GET /healthz`

Returns:

```json
{ "status": "ok" }
```

### `POST /v1/password/evaluate`

Request:

```json
{
  "username": "okenobi",
  "email": "o.kenobi@jedi-council.com",
  "password": "Hello there!"
}
```

Response:

```json
{
  "score": 3,
  "strength": "strong",
  "acceptable": false,
  "breach": {
    "checked": true,
    "breached": true,
    "occurrences": 22
  },
  "checks": {
    "minLength": true,
    "notBreached": false,
    "noUserInfo": true
  },
  "feedback": {
    "warning": "This password appeared in known data breaches.",
    "suggestions": [
      "Use a longer passphrase of unrelated words.",
      "Do not reuse passwords that may have been exposed elsewhere."
    ]
  },
  "estimatedCrackTime": "4 days"
}
```

Validation rules:

- `password` is required and must be 8-256 characters.
- `username` is optional and capped at 256 characters.
- `email` is optional, must be a valid email address, and is capped at 320 characters.
- Unknown JSON fields are rejected.

### Error responses

| Status | `error` | When |
|--------|---------|------|
| `400` | `invalid_json` | Request body is not valid JSON. |
| `400` | `validation_failed` | Required fields are missing or field values fail validation. |
| `404` | `not_found` | Route does not exist. |
| `413` | `payload_too_large` | Request body exceeds the 1 KB limit. |
| `429` | _(plain text)_ | Rate limit exceeded (100 requests per 15 minutes per IP). |
| `500` | `internal_error` | Unexpected server error. |

`400 invalid_json`:

```json
{
  "error": "invalid_json",
  "message": "Request body must be valid JSON."
}
```

`400 validation_failed`:

```json
{
  "error": "validation_failed",
  "details": [
    { "path": "password", "message": "password must contain at least 8 characters" }
  ]
}
```

`404 not_found`:

```json
{
  "error": "not_found",
  "message": "The requested resource was not found."
}
```

`413 payload_too_large`:

```json
{
  "error": "payload_too_large",
  "message": "Request body must not exceed 1 KB."
}
```

`429 too_many_requests` - plain-text body from `express-rate-limit` (for example, `Too many requests, please try again later.`). Standard `RateLimit-*` response headers are included.

`500 internal_error`:

```json
{
  "error": "internal_error",
  "message": "Unexpected error while evaluating the password."
}
```

## Security decisions

- No password composition rules are enforced. This follows NIST SP 800-63B guidance: users are not forced to include arbitrary digits, symbols, or casing patterns.
- Strength is measured with `@zxcvbn-ts/core` and language dictionaries. Username, email, email local part, and domain tokens are passed as user inputs so zxcvbn can penalize personal information.
- Passwords are checked against Have I Been Pwned using the Range API. The service sends only the first five SHA-1 hex characters, never the password or full hash.
- HIBP requests use `Add-Padding: true` and a 3 second timeout.
- If HIBP is unavailable, the service returns `breach.checked: false` and still returns the local evaluation. In this mode, `acceptable` field is based on local strength and length only.
- A confirmed breached password always returns `acceptable: false`, regardless of local zxcvbn score.
- Express is protected with `helmet`, `express-rate-limit` at 100 requests per 15 minutes, and a 1 KB JSON body limit.
- `pino-http` is configured with redaction for password, username, email fields, and authorization headers.

## Development

```bash
npm install
npm test
npm run typecheck
npm run build
npm start
```

The service listens on `HOST` (default `0.0.0.0`) and `PORT` (default `3000`). Copy `.env.example` to `.env` to override these values for local development.

Manual check:

```bash
curl -X POST http://localhost:3000/v1/password/evaluate \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"okenobi\",\"email\":\"o.kenobi@jedi-council.com\",\"password\":\"Panoramic-BlueOrbit-9341-walnut-vivid!\"}"
```

## Docker

```bash
docker build -t passcheck .
docker run --rm -p 3000:3000 passcheck
```

Or with Docker Compose:

```bash
docker compose up --build
```

The Dockerfile is multi-stage, runs tests during build, installs production dependencies only in the runtime image, runs as the non-root `node` user, and includes a `HEALTHCHECK` against `/healthz`.

## Deployment notes

- **Stateless** - no database or persistent storage; instances can be scaled horizontally behind a load balancer.
- **Outbound access** - the service needs HTTPS egress to `api.pwnedpasswords.com` for breach checks. Without it, evaluation still works locally but `breach.checked` will be `false`.
- **No built-in authentication** - deploy on an internal network or behind an API gateway / reverse proxy with auth, TLS termination, and additional rate limiting as needed.
- **Graceful shutdown** - the process handles `SIGTERM` and `SIGINT`, allowing in-flight requests to finish before exit (useful for rolling deploys in Kubernetes).
- **`checks.noUserInfo` is informational** - it does not affect the `acceptable` field; only zxcvbn score, minimum length, and breach status do.

## CI

GitHub Actions runs `npm run typecheck`, `npm test`, and `docker build` on every push and pull request to `main`.

---

# PassCheck (PL)

_Poniższa dokumentacja została przetłumaczona automatycznie z oryginalnej anglojęzycznej wersji._

Niewielki mikroserwis Express.js do oceny siły haseł w środowiskach regulowanych. Ocenia hasła za pomocą [zxcvbn](https://github.com/zxcvbn-ts/zxcvbn), sprawdza je w [Have I Been Pwned](https://haveibeenpwned.com/) z użyciem k-anonimowości (z serwera wychodzi jedynie pierwsze pięć znaków hex skrótu SHA-1) i zwraca ustrukturyzowany werdykt z oceną siły, statusem wycieku oraz praktycznymi wskazówkami. API jest zgodne z wytycznymi NIST SP 800-63B - bez wymuszania składu hasła, zawsze odrzuca hasła z wycieków, a opcjonalna nazwa użytkownika i adres e-mail pomagają wykryć dane osobowe w haśle. Bezstanowy, gotowy do konteneryzacji, przeznaczony do pracy jako wewnętrzna usługa za warstwą uwierzytelniania.

## Szybki start

```bash
git clone https://github.com/vadtrex/passcheck.git
cd passcheck
docker build -t passcheck .
docker run --rm -p 3000:3000 passcheck
```

Sprawdzenie, czy usługa działa:

```bash
curl http://localhost:3000/healthz
```

Ocena hasła:

```bash
curl -X POST http://localhost:3000/v1/password/evaluate \
  -H "Content-Type: application/json" \
  -d "{\"password\":\"Panoramic-BlueOrbit-9341-walnut-vivid!\"}"
```

## API

Specyfikacja OpenAPI 3.1: [`openapi.yaml`](openapi.yaml).

### `GET /healthz`

Zwraca:

```json
{ "status": "ok" }
```

### `POST /v1/password/evaluate`

Żądanie:

```json
{
  "username": "okenobi",
  "email": "o.kenobi@jedi-council.com",
  "password": "Hello there!"
}
```

Odpowiedź:

```json
{
  "score": 3,
  "strength": "strong",
  "acceptable": false,
  "breach": {
    "checked": true,
    "breached": true,
    "occurrences": 22
  },
  "checks": {
    "minLength": true,
    "notBreached": false,
    "noUserInfo": true
  },
  "feedback": {
    "warning": "This password appeared in known data breaches.",
    "suggestions": [
      "Use a longer passphrase of unrelated words.",
      "Do not reuse passwords that may have been exposed elsewhere."
    ]
  },
  "estimatedCrackTime": "4 days"
}
```

Zasady walidacji:

- `password` jest wymagane i musi mieć 8–256 znaków.
- `username` jest opcjonalne, maksymalnie 256 znaków.
- `email` jest opcjonalny, musi być poprawnym adresem e-mail, maksymalnie 320 znaków.
- Nieznane pola JSON są odrzucane.

### Odpowiedzi błędów

| Status | `error` | Kiedy |
|--------|---------|-------|
| `400` | `invalid_json` | Ciało żądania nie jest poprawnym JSON-em. |
| `400` | `validation_failed` | Brakuje wymaganych pól lub wartości nie przechodzą walidacji. |
| `404` | `not_found` | Trasa nie istnieje. |
| `413` | `payload_too_large` | Ciało żądania przekracza limit 1 KB. |
| `429` | _(zwykły tekst)_ | Przekroczono limit żądań (100 na 15 minut na IP). |
| `500` | `internal_error` | Nieoczekiwany błąd serwera. |

`400 invalid_json`:

```json
{
  "error": "invalid_json",
  "message": "Request body must be valid JSON."
}
```

`400 validation_failed`:

```json
{
  "error": "validation_failed",
  "details": [
    { "path": "password", "message": "password must contain at least 8 characters" }
  ]
}
```

`404 not_found`:

```json
{
  "error": "not_found",
  "message": "The requested resource was not found."
}
```

`413 payload_too_large`:

```json
{
  "error": "payload_too_large",
  "message": "Request body must not exceed 1 KB."
}
```

`429 too_many_requests` - ciało odpowiedzi w postaci zwykłego tekstu z `express-rate-limit` (np. `Too many requests, please try again later.`). Dołączane są standardowe nagłówki `RateLimit-*`.

`500 internal_error`:

```json
{
  "error": "internal_error",
  "message": "Unexpected error while evaluating the password."
}
```

## Decyzje bezpieczeństwa

- Nie wymuszamy reguł składu hasła. Zgodnie z NIST SP 800-63B użytkownicy nie muszą dodawać cyfr, symboli ani wielkości liter według sztywnego schematu.
- Siłę mierzy `@zxcvbn-ts/core` ze słownikami językowymi. Nazwa użytkownika, e-mail, część lokalna i tokeny domeny są przekazywane do zxcvbn, aby karać hasła zawierające dane osobowe.
- Hasła sprawdzane są w Have I Been Pwned przez Range API. Usługa wysyła tylko pierwsze pięć znaków hex SHA-1, nigdy hasła ani pełnego skrótu.
- Żądania HIBP używają `Add-Padding: true` i limitu czasu 3 sekundy.
- Gdy HIBP jest niedostępne, usługa zwraca `breach.checked: false` i nadal podaje lokalną ocenę. W tym trybie pole `acceptable` opiera się wyłącznie na lokalnej sile i długości hasła.
- Potwierdzony wyciek zawsze daje `acceptable: false`, niezależnie od wyniku zxcvbn.
- Express jest chroniony przez `helmet`, `express-rate-limit` (100 żądań na 15 minut) oraz limit ciała JSON 1 KB.
- `pino-http` maskuje w logach hasło, nazwę użytkownika, e-mail oraz nagłówki autoryzacji.

## Rozwój

```bash
npm install
npm test
npm run typecheck
npm run build
npm start
```

Usługa nasłuchuje na `HOST` (domyślnie `0.0.0.0`) i `PORT` (domyślnie `3000`). Skopiuj `.env.example` do `.env`, aby nadpisać te wartości podczas lokalnego rozwoju.

Ręczne sprawdzenie:

```bash
curl -X POST http://localhost:3000/v1/password/evaluate \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"okenobi\",\"email\":\"o.kenobi@jedi-council.com\",\"password\":\"Panoramic-BlueOrbit-9341-walnut-vivid!\"}"
```

## Docker

```bash
docker build -t passcheck .
docker run --rm -p 3000:3000 passcheck
```

Lub przez Docker Compose:

```bash
docker compose up --build
```

Plik Dockerfile jest wieloetapowy: uruchamia testy podczas budowy, w obrazie produkcyjnym instaluje tylko zależności runtime, działa jako użytkownik `node` (nie root) i zawiera `HEALTHCHECK` na `/healthz`.

## Wdrożenie

- **Bezstanowy** - brak bazy danych i trwałego storage; instancje można skalować horyzontalnie za load balancerem.
- **Dostęp wychodzący** - usługa wymaga HTTPS do `api.pwnedpasswords.com` w celu sprawdzania wycieków. Bez tego ocena lokalna nadal działa, ale `breach.checked` będzie `false`.
- **Brak wbudowanego uwierzytelniania** - wdrażaj w sieci wewnętrznej lub za API gateway / reverse proxy z auth, TLS i dodatkowym rate limitingiem.
- **Graceful shutdown** - proces obsługuje `SIGTERM` i `SIGINT`, pozwalając dokończyć trwające żądania (przydatne przy rolling deploy w Kubernetes).
- **`checks.noUserInfo` ma charakter informacyjny** - nie wpływa na pole `acceptable`; liczy się wynik zxcvbn, minimalna długość i status wycieku.

## CI

GitHub Actions uruchamia `npm run typecheck`, `npm test` oraz `docker build` przy każdym pushu i pull requeście do `main`.
