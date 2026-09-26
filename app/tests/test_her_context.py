"""Test that context slicing respects max_her_messages."""
import _bootstrap  # noqa: F401  (puts app/ on sys.path)
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from native_analysis import _slice_by_her_count


def test_slice_by_her_count():
    # Create 20 messages: alternating her/me (index 0,2,4... = her; 1,3,5... = me)
    messages = []
    for i in range(20):
        who = "her" if i % 2 == 0 else "me"
        messages.append((f"id{i}", i, who, f"text{i}", "content"))

    # Test 1: End at index 18 (her), max 5 her messages
    result = _slice_by_her_count(messages, 18, 5)
    her_count = sum(1 for msg in result if msg[0] == "her")
    print(f"Test 1: her_count={her_count}, total={len(result)}")
    print(f"  Messages: {[(msg[0], msg[1]) for msg in result]}")
    assert her_count <= 5, f"Expected ≤5 her messages, got {her_count}"
    assert result[-1][0] == "her", f"Last message should be 'her', got {result[-1][0]}"
    assert result[-1][1] == "text18", f"Last message should be text18, got {result[-1][1]}"

    # Test 2: End at index 10 (her), max 3 her messages
    result = _slice_by_her_count(messages, 10, 3)
    her_count = sum(1 for msg in result if msg[0] == "her")
    print(f"Test 2: her_count={her_count}, total={len(result)}")
    print(f"  Messages: {[(msg[0], msg[1]) for msg in result]}")
    assert her_count <= 3, f"Expected ≤3 her messages, got {her_count}"
    assert result[-1][0] == "her", f"Last message should be 'her', got {result[-1][0]}"

    # Test 3: Only 2 her messages available, max 5
    messages_short = [
        ("id0", 0, "me", "text0", "content"),
        ("id1", 1, "her", "text1", "content"),
        ("id2", 2, "me", "text2", "content"),
        ("id3", 3, "her", "text3", "content"),
    ]
    result = _slice_by_her_count(messages_short, 3, 5)
    her_count = sum(1 for msg in result if msg[0] == "her")
    print(f"Test 3: her_count={her_count}, total={len(result)}")
    print(f"  Messages: {[(msg[0], msg[1]) for msg in result]}")
    assert her_count == 2, f"Expected 2 her messages, got {her_count}"
    assert len(result) == 4, f"Expected all 4 messages, got {len(result)}"

    print("\nAll tests passed!")


if __name__ == "__main__":
    test_slice_by_her_count()
