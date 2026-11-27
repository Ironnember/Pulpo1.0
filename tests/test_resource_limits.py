import json
import unittest

from pulpo.resource_limits import ResourceLimitError, load_bounded_json


class ResourceLimitTests(unittest.TestCase):
    def test_accepts_small_bounded_json(self):
        value = load_bounded_json(
            b'{"ok":true,"items":[1,2,3]}',
            max_bytes=128,
            max_depth=8,
            max_items=16,
            max_string_chars=32,
        )
        self.assertEqual([1, 2, 3], value["items"])

    def test_rejects_byte_depth_item_and_string_exhaustion(self):
        with self.assertRaisesRegex(ResourceLimitError, "byte"):
            load_bounded_json(b'{"x":"123456"}', max_bytes=4)
        nested = json.dumps({"a": {"b": {"c": {"d": 1}}}})
        with self.assertRaisesRegex(ResourceLimitError, "depth"):
            load_bounded_json(nested, max_bytes=1024, max_depth=3)
        with self.assertRaisesRegex(ResourceLimitError, "item"):
            load_bounded_json(json.dumps(list(range(20))), max_bytes=1024, max_items=10)
        with self.assertRaisesRegex(ResourceLimitError, "string"):
            load_bounded_json(json.dumps({"x": "z" * 50}), max_bytes=1024, max_string_chars=16)


if __name__ == "__main__":
    unittest.main()
