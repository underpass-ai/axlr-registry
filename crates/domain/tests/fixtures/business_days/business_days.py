#!/usr/bin/env python3
"""Business-day arithmetic: count working days between dates, add working days to a date,
or list the working days of a range. Weekends and an explicit holiday list are skipped.

Input (JSON on stdin):
  operation  "count" | "add" | "list"
  start      "YYYY-MM-DD"
  end        "YYYY-MM-DD"   (count, list; inclusive)
  days       integer        (add; may be negative)
  holidays   ["YYYY-MM-DD", ...]   optional
  weekend    [6, 7]         optional ISO weekdays that are not working days (default Saturday, Sunday)
"""
import datetime as dt
import json
import sys


def fail(message):
    print(json.dumps({"error": message}))
    sys.exit(2)


def parse(value, field):
    try:
        return dt.date.fromisoformat(value)
    except (TypeError, ValueError):
        fail(f"{field} must be a date YYYY-MM-DD")


def main():
    try:
        request = json.load(sys.stdin)
    except ValueError as error:
        fail(f"stdin is not JSON: {error}")
    operation = request.get("operation")
    weekend = set(request.get("weekend", [6, 7]))
    holidays = {parse(h, "holidays[]") for h in request.get("holidays", [])}
    working = lambda d: d.isoweekday() not in weekend and d not in holidays
    start = parse(request.get("start"), "start")
    if operation in ("count", "list"):
        end = parse(request.get("end"), "end")
        if end < start:
            fail("end is before start")
        days = [start + dt.timedelta(i) for i in range((end - start).days + 1)]
        found = [d for d in days if working(d)]
        result = {"operation": operation, "start": start.isoformat(), "end": end.isoformat(), "business_days": len(found),
                  "calendar_days": len(days)}
        if operation == "list":
            result["days"] = [d.isoformat() for d in found]
    elif operation == "add":
        days = request.get("days")
        if not isinstance(days, int):
            fail("days must be an integer")
        step = 1 if days >= 0 else -1
        current, left = start, abs(days)
        while left:
            current += dt.timedelta(step)
            if working(current):
                left -= 1
        result = {"operation": "add", "start": start.isoformat(), "days": days, "result": current.isoformat(),
                  "weekday": current.strftime("%A")}
    else:
        fail("operation must be count, add or list")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
