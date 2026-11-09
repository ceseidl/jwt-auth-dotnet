[English](README.md) | Português

# Autenticação JWT no ASP.NET Core, para iniciantes

Uma minimal API do ASP.NET Core 10 com o caminho inteiro: cadastro com
senha em hash, login, access token (JWT) e refresh token com rotação,
validação a cada requisição e a diferença entre 401 e 403. Um programa
de laboratório sobe a API em `localhost`, chama por HTTP e mostra o que
aconteceu, inclusive as armadilhas.

Artigo: https://ceseidl.com.br/artigos/

## Estrutura

- `src/AuthApi`: a API (`/auth/register`, `/auth/login`,
  `/auth/refresh`, `/me` e `/admin/report`). Usuários e refresh tokens
  ficam em memória.
- `lab/AuthLab`: 7 partes: fluxo, tokens ruins (401), papéis (403),
  rotação do refresh token, papel enviado pelo cliente, hash da senha
  e tempo do login.
- `tests/AuthApi.Tests`: 8 testes xUnit com `WebApplicationFactory`.
- `outputs`: três execuções completas do lab e as partes usadas no artigo.

## Rodar

```bash
dotnet test
dotnet run -c Release --project lab/AuthLab
dotnet run --project src/AuthApi --environment Development
```

## Observações

- O `appsettings.Development.json` tem uma chave de assinatura e um
  usuário administrador só para rodar local. Em produção, a chave vem
  de variável de ambiente ou de um cofre de segredos.
- Os tempos foram medidos com cliente e servidor na mesma máquina.
