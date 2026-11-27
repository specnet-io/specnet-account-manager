#!/usr/bin/env bash
# Integration tests: real OpenLDAP (LDAPS + StartTLS) and Postgres in throwaway containers. See DETAILS.md §Testing.
set -euo pipefail
cd "$(dirname "$0")/.."

DOCKER=${DOCKER:-docker}
NET=sam-it
cleanup() { $DOCKER rm -f sam-it-ldap sam-it-pg >/dev/null 2>&1 || true; $DOCKER network rm $NET >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
$DOCKER network create $NET >/dev/null

$DOCKER run -d --name sam-it-ldap --network $NET --hostname ldap.sam.test \
  -e LDAP_DOMAIN=sam.test -e LDAP_ADMIN_PASSWORD=it-admin-pw -e LDAP_TLS_VERIFY_CLIENT=never \
  docker.io/osixia/openldap:1.5.0 >/dev/null
$DOCKER run -d --name sam-it-pg --network $NET \
  -e POSTGRES_PASSWORD=it-pg-pw -e POSTGRES_DB=sam \
  docker.io/library/postgres:17-alpine >/dev/null

echo "waiting for OpenLDAP..."
for _ in $(seq 60); do
  $DOCKER exec sam-it-ldap ldapsearch -x -H ldap://localhost -b dc=sam,dc=test -D cn=admin,dc=sam,dc=test -w it-admin-pw -s base >/dev/null 2>&1 && break
  sleep 1
done
# openssh-lpk schema for sshPublicKey
$DOCKER exec -i sam-it-ldap ldapadd -Y EXTERNAL -H ldapi:/// >/dev/null 2>&1 <<'LDIF' || true
dn: cn=openssh-lpk,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: openssh-lpk
olcAttributeTypes: ( 1.3.6.1.4.1.24552.500.1.1.1.13 NAME 'sshPublicKey' DESC 'OpenSSH public key' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
olcObjectClasses: ( 1.3.6.1.4.1.24552.500.1.1.2.0 NAME 'ldapPublicKey' SUP top AUXILIARY DESC 'OpenSSH LPK objectclass' MAY ( sshPublicKey $ uid ) )
LDIF

echo "waiting for Postgres..."
for _ in $(seq 60); do
  $DOCKER exec sam-it-pg pg_isready -U postgres >/dev/null 2>&1 && break
  sleep 1
done

LDAP_IP=$($DOCKER inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' sam-it-ldap)
PG_IP=$($DOCKER inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' sam-it-pg)

export SAM_TEST_LDAP_BIND_DN=cn=admin,dc=sam,dc=test SAM_TEST_LDAP_BIND_PASSWORD=it-admin-pw SAM_TEST_LDAP_BASE_DN=dc=sam,dc=test
export SAM_TEST_POSTGRES="postgres://postgres:it-pg-pw@${PG_IP}:5432/sam?sslmode=disable"

echo "== LDAPS"
SAM_TEST_LDAP_URL="ldaps://${LDAP_IP}:636" go test -tags integration -count=1 -run Integration -v ./internal/directory/ | grep -E "^(--- |ok|FAIL)"
echo "== LDAP + StartTLS"
SAM_TEST_LDAP_URL="ldap://${LDAP_IP}:389" go test -tags integration -count=1 -run Integration -v ./internal/directory/ | grep -E "^(--- |ok|FAIL)"
echo "== Postgres store"
go test -count=1 -run TestStore -v ./internal/store/ | grep -E '^(=== RUN|--- |ok|FAIL)'
