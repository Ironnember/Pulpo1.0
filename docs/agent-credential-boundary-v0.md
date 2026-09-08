# Agent Credential Boundary v0

Status: Proposed implementation proof. Successful tests are not authority to merge.

## Constitutional statement

`CERTIFICATION != AUTHORITY`

An agent credential is portable evidence that an identified agent has demonstrated a qualification under a named issuer and scope. It is not a directive, policy, approval, authority grant, budget grant, permit, execution handle, or provider credential.

The intended sequence is:

`agent identity -> credential evidence -> eligibility assessment -> existing Pulpo authority/policy/directive decision -> one-use permit -> execution -> evidence -> reconciliation`

A positive credential assessment may satisfy a policy prerequisite. It must never independently authorize a consequential action or broaden an existing directive.

## V0 object

`AgentCredential` binds:

- credential ID;
- issuer ID;
- subject principal;
- qualification;
- explicit scopes;
- issue and expiry bounds;
- assessment/evidence digest;
- revocation reference;
- schema version;
- deterministic credential hash.

`CredentialEvaluator` checks only eligibility predicates supplied by the existing governance context: trusted issuer, revocation status, validity time, exact subject, qualification, and scope.

V0 deliberately has no dependency on the governance kernel, authority client, directive controller, permit state, executor, provider, budget account, or outcome memory.

## Proof invariants

1. A matching credential can produce `credential_eligible`.
2. An untrusted issuer cannot establish eligibility.
3. A revoked or expired credential cannot establish eligibility.
4. A credential cannot transfer between agent identities.
5. Qualification or scope substitution fails closed.
6. Neither the credential nor its assessment contains an authority grant, permit, execution handle, provider credential, or budget grant.
7. Credential accumulation does not change authority by itself.

## Explicit non-claims

V0 does not prove a SANS-issued machine credential exists, that SANS permits autonomous agents to sit its human certification exams, or that any external certifier recognizes an AI agent as a credential holder. Those require external issuer participation and terms.

V0 does not make Pulpo a certification authority. Issuer trust remains an input to existing governance and must not become a second trust registry.

V0 does not yet prove cryptographic issuer verification. `evidence_digest` and `revocation_ref` preserve the required object boundary; issuer-signature verification is a later proof and must reuse the existing cryptographic/trust seams rather than invent another authority service.

## Next proof

Use one independently issued machine-verifiable competence artifact, bind it to one authenticated agent identity, and demonstrate the same action under two conditions:

- credential valid but no execution authority -> zero consequence;
- credential valid plus separately valid authority -> exactly the normal Pulpo-governed consequence path.

The critical negative control is that certification alone must produce zero permits and zero provider transmissions.
