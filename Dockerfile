FROM openpolicyagent/opa:0.63.0
COPY policy.rego /policy.rego
EXPOSE 8181
CMD ["run","--server","--addr=0.0.0.0:8181","/policy.rego"]