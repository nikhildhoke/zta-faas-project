package authz

default allow = false

allow {
  input.method == "GET"
  input.user == "test-zta-user"
}

