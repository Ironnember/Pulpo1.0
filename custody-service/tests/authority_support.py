def trust_for(verifier: HmacTestVerifier) -> AuthorityTrust:
    """
    Construct an AuthorityTrust dataclass from the verifier's canonical fields.
    """
    return AuthorityTrust(
        authority_id=getattr(verifier, "authority_id", ""),
        verifier_id=getattr(verifier, "verifier_id", ""),
        key_id=getattr(verifier, "key_id", ""),
        algorithm=getattr(verifier, "algorithm", ""),
        key_fingerprint=getattr(verifier, "key_fingerprint", ""),
        deployment_id=getattr(verifier, "deployment_id", ""),
        max_approval_ttl_ns=int(getattr(verifier, "max_approval_ttl_ns", 0) or 0),
        schema=getattr(verifier, "schema", ""),
    )
