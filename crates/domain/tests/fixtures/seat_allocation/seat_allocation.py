#!/usr/bin/env python3
"""Allocate seats among parties: D'Hondt, Sainte-Laguë (plain or modified) or Hare quota.

Input (one JSON object on stdin):
  seats     integer > 0
  votes     object {party: votes >= 0}
  method    "dhondt" (default) | "sainte_lague" | "modified_sainte_lague" | "hare"
  threshold number in [0, 100): parties under this share of valid votes get no seats (default 0)
Output (JSON on stdout):
  seats per party, the order in which seats were awarded (divisor methods), the last quotient
  per party, and which parties the threshold excluded. Ties go to the larger vote count, then
  to the party name, and are reported.
"""
import json
import sys
from fractions import Fraction


def fail(message):
    print(json.dumps({"error": message}))
    sys.exit(2)


def divisor_method(seats, votes, divisors):
    awarded = {p: 0 for p in votes}
    order = []
    ties = []
    for _ in range(seats):
        quotients = {p: Fraction(v, divisors(awarded[p])) for p, v in votes.items()}
        best = max(quotients.values())
        winners = sorted((p for p, q in quotients.items() if q == best), key=lambda p: (-votes[p], p))
        if len(winners) > 1:
            ties.append({"between": winners, "awarded_to": winners[0]})
        awarded[winners[0]] += 1
        order.append({"party": winners[0], "quotient": str(best)})
    return awarded, order, ties


def hare(seats, votes):
    total = sum(votes.values())
    quota = Fraction(total, seats)
    awarded = {p: int(Fraction(v) / quota) for p, v in votes.items()}
    remainders = {p: Fraction(v) / quota - awarded[p] for p, v in votes.items()}
    left = seats - sum(awarded.values())
    ties = []
    ranking = sorted(votes, key=lambda p: (-remainders[p], -votes[p], p))
    for p in ranking[:left]:
        awarded[p] += 1
    if left and len(ranking) > left and remainders[ranking[left - 1]] == remainders[ranking[left]]:
        ties.append({"between": [ranking[left - 1], ranking[left]], "awarded_to": ranking[left - 1]})
    return awarded, [{"party": p, "remainder": str(remainders[p])} for p in ranking[:left]], ties


def main():
    try:
        request = json.load(sys.stdin)
    except ValueError as error:
        fail(f"stdin is not JSON: {error}")
    seats = request.get("seats")
    votes = request.get("votes")
    method = request.get("method", "dhondt")
    threshold = request.get("threshold", 0)
    if not isinstance(seats, int) or seats <= 0:
        fail("seats must be a positive integer")
    if not isinstance(votes, dict) or not votes or any(not isinstance(v, int) or v < 0 for v in votes.values()):
        fail("votes must be a non-empty object of non-negative integers")
    valid = sum(votes.values())
    if valid == 0:
        fail("no valid votes")
    excluded = [p for p, v in votes.items() if Fraction(v * 100, valid) < Fraction(str(threshold))]
    eligible = {p: v for p, v in votes.items() if p not in excluded and v > 0}
    if not eligible:
        fail("no party passes the threshold")
    if method == "dhondt":
        awarded, order, ties = divisor_method(seats, eligible, lambda s: s + 1)
    elif method == "sainte_lague":
        awarded, order, ties = divisor_method(seats, eligible, lambda s: 2 * s + 1)
    elif method == "modified_sainte_lague":
        awarded, order, ties = divisor_method(seats, eligible, lambda s: Fraction(7, 5) if s == 0 else 2 * s + 1)
    elif method == "hare":
        awarded, order, ties = hare(seats, eligible)
    else:
        fail("method must be dhondt, sainte_lague, modified_sainte_lague or hare")
    for p in excluded:
        awarded[p] = 0
    print(json.dumps({
        "method": method,
        "seats": seats,
        "valid_votes": valid,
        "allocation": dict(sorted(awarded.items(), key=lambda kv: (-kv[1], -votes[kv[0]], kv[0]))),
        "order": order,
        "excluded_by_threshold": excluded,
        "ties": ties,
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
