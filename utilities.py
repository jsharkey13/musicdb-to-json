import struct


# Data validation functions:

def expect[T](actual:T, expected:T, message: str):
    if actual != expected:
        raise ValueError(f"{message} (expected: {expected}, actual: {actual})")


def expect_one_of[T](actual: T, expected_patterns: list[T | None], message: str):
    if any(actual == x for x in expected_patterns):
        return
    raise ValueError(f"{message} (expected: {expected_patterns}, actual: {actual})")


# Data wrangling functions:

def _unpack_one(fmt: str, struct_bytes: bytes) -> any:
    return struct.unpack(fmt, struct_bytes)[0]


def _macos_to_unix(time: int) -> int:
    """Convert MacOS epoch time to Unix epoch time."""
    return time - 2082844800 if time != 0 else 0


def _bytes_to_id(byte_values: bytes):
    if byte_values.strip(b"\0") == b"":
        return None
    return byte_values[::-1].hex().upper()


def _content_rating_flag_to_value(content_rating_flag: int) -> str | None:
    expect_one_of(content_rating_flag, [0, 1, 2, 4], "unexpected content rating flag!")
    return {0: None, 1: "explicit", 2: "clean", 4: "parental guidance?"}[content_rating_flag]


def _volume_int_to_percent(volume_adjustment: int) -> int:
    if not -255 <= volume_adjustment <= 255:
        raise ValueError(f"unexpected volume adjustment, outside -255-255 range: {volume_adjustment}!")
    volume_percent = (100.0 * volume_adjustment) / 255
    return int(volume_percent)


def _is_one(integer: int) -> bool:
    return integer == 1


def _version_bytes_to_str(version_bytes: bytes) -> str:
    return version_bytes.strip(b"\0").decode("ascii")
