package zta

default allow = false

allow {
  input.method == "GET"
  input.path == "/echo"
  input.claims.token_use == "access"
  input.claims.client_id == input.client
  contains(input.claims.scope, "openid")
}

contains(scope, s) {
  some i
  split(scope, " ")[i] == s
}
