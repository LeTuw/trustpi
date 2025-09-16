def generate_wallet_summary(result):
    """
    Generate a natural-language summary from PiTrust calculation.
    Expects the dict returned by calculate_pi_trust().
    """
    score = result["pi_trust_score"]
    cat = result["category"]
    c = result["components"]

    highlights = []

    # Payment reliability
    if c["payment_reliability"] > 750:
        highlights.append("strong and reliable payments")
    elif c["payment_reliability"] < 400:
        highlights.append("unreliable payment history")

    # Account tenure
    if c["account_tenure"] > 700:
        highlights.append("long-standing account")
    elif c["account_tenure"] < 400:
        highlights.append("relatively new account")

    # Network strength
    if c["network_strength"] > 700:
        highlights.append("well-connected within the network")
    elif c["network_strength"] < 400:
        highlights.append("weak network activity")

    # Balance health
    if c["balance_health"] > 700:
        highlights.append("healthy balance levels")
    elif c["balance_health"] < 400:
        highlights.append("low or unstable balance")

    # On-chain attestations
    if c["onchain_attestations"] > 700:
        highlights.append("several on-chain attestations")
    elif c["onchain_attestations"] < 400:
        highlights.append("few verifiable on-chain attestations")

    # Build final sentence
    if highlights:
        desc = ", ".join(highlights[:-1]) + (", and " + highlights[-1] if len(highlights) > 1 else highlights[0])
    else:
        desc = "balanced performance across all categories"

    return f"This wallet has a {cat} trust score ({score}/1000), showing {desc}."
