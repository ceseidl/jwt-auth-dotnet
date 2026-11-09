English | [Português](README.pt-BR.md)

# JWT authentication in ASP.NET Core, for beginners

An ASP.NET Core 10 minimal API with the whole path: register with a
hashed password, login, access token (JWT) and refresh token with
rotation, validation on every request, and the difference between
401 and 403. A lab program starts the real API on `localhost`, calls
it over HTTP and prints what happened, including the traps.

Article (pt-BR): https://ceseidl.com.br/artigos/

## Layout

- `src/AuthApi`: the API. `POST /auth/register`, `POST /auth/login`,
  `POST /auth/refresh`, `GET /me` (any logged-in user) and
  `GET /admin/report` (role `admin`). Users and refresh tokens live
  in memory.
- `lab/AuthLab`: 7 parts: the flow, bad tokens (401), roles (403),
  refresh rotation, role sent by the client, the password hash and
  login timing.
- `tests/AuthApi.Tests`: 8 xUnit tests with `WebApplicationFactory`.
- `outputs`: three full runs of the lab (`saida-1..3.txt`) and the
  parts used in the article (`parte-1..7.txt`).

## Run

```bash
dotnet test
dotnet run -c Release --project lab/AuthLab
dotnet run -c Release --project lab/AuthLab -- 2 7
dotnet run --project src/AuthApi --environment Development
```

## What the lab shows

- The payload is readable by anyone: `email` and `role` in plain JSON.
- Editing the payload gives 401, with a confusing message
  ("The signature key was not found").
- A token that expired 60 s ago is rejected with `ClockSkew` = 30 s
  and accepted (200) with the default of 5 minutes.
- With `MapInboundClaims = false` and `RoleClaimType` left at
  `ClaimTypes.Role`, an admin gets 403 with no error in the log.
- Taking the role from the request body turns anyone into an admin.
- Reusing a refresh token revokes the whole family, but the access
  token issued with it keeps working until it expires.
- Without a dummy hash, login for an unknown email answered in
  0.7 ms against ~63 ms for a known one.

## Notes

- `appsettings.Development.json` has a local demo signing key and an
  admin user (`admin@shop.test`). Never use them outside your machine;
  in production the key comes from an environment variable or a vault.
- Timings were measured with client and server on the same machine.
