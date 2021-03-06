# `Silhouette REST MongoDB Seed`

Example project for Play Framework that uses [Silhouette](https://github.com/mohiva/play-silhouette) for authentication and authorization, exposed REST API for sign-up, sign-in.

## Basic usage

### Sign-up

```bash
$ curl http://localhost:9000/api/auth/register \
       --header 'Content-Type: application/json' \
       --data '{"email": "adam.zareba@test.pl", "password": "this!Password!Is!Very!Very!Strong!", "fullName": "Adam Zareba", "terms": true}' \
       --verbose
```

```
< HTTP/1.1 200 OK
< Content-Type: application/json; charset=utf-8
< X-Auth-Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...

{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "expiresOn": "2017-10-06T07:49:27.238+02:00"
}
```

### Sign-in

_Not necessary just after the sign-up because you already have a valid token._

```bash
$ curl http://localhost:9000/api/auth/login \
       --header 'Content-Type: application/json' \
       --data '{"email": "adam.zareba@test.pl", "password": "this!Password!Is!Very!Very!Strong!"}' \
       --verbose
```

```
< HTTP/1.1 200 OK
< Content-Type: application/json; charset=utf-8
< X-Auth-Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...

{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "expiresOn": "2017-10-06T07:49:27.238+02:00"
}
```

### Secured Action with autorization

_capture the token_

```
$ export JWT_TOKEN=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

_The token must belong to a user with Admin role_

```bash
$ curl http://localhost:9000/api/badPassword --header X-Auth-Token:$JWT_TOKEN --verbose
```

```
< HTTP/1.1 200 OK
< Content-Type: application/json; charset=utf-8

{"result":"qwerty1234"}
```
## Built-in users

| username    | password        |
| ----------- |:---------------:|
| test1       | test1Password   |
| test2       | test2Password   |

## Database reload

It is possible to reload database with based data with scripts:
[recreate.bat](database/recreate.bat) or [recreate.sh](database/recreate.sh)

Using Docker: see the [database](./database) section

## API documentation

Documentation is available under address: [REST API](http://localhost:9000/docs)

# License

The code is licensed under [Apache License v2.0](http://www.apache.org/licenses/LICENSE-2.0). 
