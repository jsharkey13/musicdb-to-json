import struct
import zlib
from io import BytesIO

from Crypto.Cipher import AES

# See https://home.vollink.com/gary/playlister/musicdb.html
# for a detailed analysis, and the source of much of the byte offset
# and data interpretations in the parse functions.
# See # https://github.com/rinsuki/musicdb2sqlite for the inspiration
# for this script and library.

BOMA_UTF_SUBTYPES = {
    # All of these boma chunks have a type/encoding property at bytes 20-23
    # that indicates UTF-8/ASCII or UTF-16.
    0x2:  "name",
    0x3:  "album",
    0x4:  "artist",
    0x5:  "genre",
    0x6:  "localized_file_type",
    0x7:  "equalizer_id",
    0x8:  "comment",
    0xB:  "url",
    0xC:  "composer",
    0xE:  "classical_grouping",
    0x12: "episode_description",
    0x16: "episode_synopsis",
    0x18: "series_title",
    0x19: "episode_number",
    0x1B: "album_artist",
    0x1C: "content_rating",
    0x1E: "sort_name",
    0x1F: "sort_album",
    0x20: "sort_artist",
    0x21: "sort_album_artist",
    0x22: "sort_composer",
    0x2B: "isrc",
    0x2E: "copyright",
    0x34: "itunes_store_flavor",
    0x3B: "purchaser_username",
    0x3C: "purchaser_name",
    0x3F: "classical_work_name",
    0x40: "classical_movement_name",
    0x43: "filepath",
    0xC8: "name",  # playlist
    0x12C: "name",  # album
    0x12D: "artist",  # album
    0x12E: "album_artist",  # album
    0x12F: "series_title",
    0x190: "name",  # artist
    0x191: "sort_name",  # artist
    0x1F8: "media_folder_uri_root",  # library
}
BOMA_SHORT_UTF16_SUBTYPES = {
    # These boma chunks are stored without an indication of encoding but are UTF-16.
    0x1FD: "media_folder",  # library
    0x200: "media_folder_repeated",  # library
}
BOMA_SHORT_UTF8_SUBTYPES = {
    # These boma chunks are stored without an indication of encoding but are UTF-8/ASCII.
    0x1FC: "imported_itl_filepath",  # library
}
BOMA_IGNORE_SUBTYES = {
    # These boma chunks are either unwanted or currently undeciphered.
    # Those ending "_plist" are XML plist objects which could be parsed if desired.
    # Those starting with a "?" are unknown, with some rough description.
    0x1D:  "asset_info_plist",
    0x36:  "artwork_plist",
    0x38:  "redownload_params_plist",
    0xC9:  "?smart_playlist_settings",
    0xCA:  "?unknown_playlist_boma",
    0xCD:  "generated_artwork_uuids_plist",
    0x192: "artwork_url_plist",
    0x1F6: "?unknown_lpma_boma",
    0x1FF: "?unknown_lpma_boma",
}


# Data validation functions:

def expect[T](actual:T, expected:T, message: str):
    if actual != expected:
        raise ValueError(f"{message} (expected: {expected}, actual: {actual})")


def expect_one_of[T](actual: T, expected_patterns: list[T], message: str):
    if any(actual == x for x in expected_patterns):
        return
    raise ValueError(f"{message} (expected: {expected_patterns}, actual: {actual})")


# Data wrangling functions:

def merge_in(source: dict[str: any], extra: dict[str: any]) -> None:
    """Merge an extra dict into the source dict.
       Concatenate clashing list values, recursively merge clashing dict values,
       but overwrite all other clashing keys.
    """
    for key, value in extra.items():
        if type(source.get(key)) is list and type(extra[key]) is list:
            source[key].extend(extra[key])
        elif type(source.get(key)) is dict and type(extra[key]) is dict:
            merge_in(source[key], extra[key])
        else:
            source[key] = extra[key]


def _unpack_one(fmt: str, struct_bytes: bytes) -> any:
    return struct.unpack(fmt, struct_bytes)[0]


def _macos_to_unix(time: int) -> int:
    """Convert MacOS epoch time to Unix epoch time."""
    return time - 2082844800 if time != 0 else 0


def _bytes_to_id(byte_values: bytes):
    return byte_values[::-1].hex().upper()


def _content_rating_flag_to_value(content_rating_flag: int) -> str | None:
    expect_one_of(content_rating_flag, [0, 1, 2, 4], "unexpected content rating flag!")
    return {0: None, 1: "explicit", 2: "clean", 4: "parental guidance?"}[content_rating_flag]


def _volume_int_to_percent(volume_adjustment: int) -> int:
    if not -255 <= volume_adjustment <= 255:
        raise ValueError(f"unexpected volume adjustment, outside -255-255 range: {volume_adjustment}!")
    volume_percent = (100.0 * volume_adjustment) / 255
    return int(volume_percent)


# Data loading functions:

def get_library_bytes(library_filename: str, key: str) -> bytes:
    if type(key) is not str and len(key) != 16 and not key.startswith("BHU"):
        raise ValueError("Incorrect decryption key provided! The key should be 16 characters long.")

    with open(library_filename, "rb") as library_file:
        file_bytes = library_file.read()

    expect(file_bytes[:4], b"hfma", "musicdb file should start with hfma chunk!")
    header_size = _unpack_one("<I", file_bytes[4:4 + 4])
    file_size = _unpack_one("<I", file_bytes[8:8 + 4])
    expect(len(file_bytes), file_size, "file size metadata mismatch!")
    data_size = file_size - header_size

    # Some (but not all!) of the library data is encrypted. Apparently we decrypt the encrypted bytes:
    encrypted_size = _unpack_one("<I", file_bytes[84:84 + 4])
    encrypted_size = data_size - (data_size % 16) if encrypted_size > file_size else encrypted_size
    decrypted = b""
    if encrypted_size > 0:
        key_bytes = key.encode("ascii")
        decrypted = AES.new(key_bytes, AES.MODE_ECB).decrypt(file_bytes[header_size:header_size + encrypted_size])
    # Then we just append on the rest of the file (which is not encrypted) and decompress:
    raw_bytes = zlib.decompress(decrypted + file_bytes[header_size + encrypted_size:])
    raw_bytes = file_bytes[:header_size] + raw_bytes
    return raw_bytes


def read_next_chunk(bytestream: BytesIO) -> None | tuple[bytes, bytes]:
    # Read a fixed amount to get the chunk metadata:
    initial_read_size = 12
    chunk_bytes = bytestream.read(initial_read_size)
    if chunk_bytes == b"":
        return None
    # Work out how long the chunk is:
    chunk_type = chunk_bytes[:4]
    length_byte_offset = 8 if chunk_type == b"boma" else 4
    chunk_length = _unpack_one("<I", chunk_bytes[length_byte_offset:length_byte_offset + 4])
    # Read the rest and return it:
    chunk_bytes += bytestream.read(chunk_length - initial_read_size)
    return chunk_type, chunk_bytes


# Beyond this point are functions for decoding the byte values contained in the various chunk types.
# There are also some functions "hide_known_..." which blank out known byte ranges to help with
# deciphering the remaining unknown sections.

# Section master functions:

def _validated_master_metadata(master_bytes: bytes, expected_type: bytes, subtype: bytes) -> dict[str: any]:
    metadata = {}
    expected_type_str = expected_type.decode("utf-8")
    subtype_str = subtype.decode("utf-8")
    #
    expect(master_bytes[:4], expected_type, f"not a {expected_type_str} chunk!")
    byte_length = _unpack_one("<I", master_bytes[4:4 + 4])
    expect(byte_length, len(master_bytes), f"{expected_type_str} section length mismatch!")
    metadata["byte_length"] = byte_length
    metadata[f"{subtype_str}_sections"] = _unpack_one("<I", master_bytes[8:8 + 4])

    return metadata

## hfma functions:

def parse_hfma(hfma_bytes: bytes) -> (dict[str: any], dict[str: any]):
    # Some of this will duplicate behaviour in get_library_bytes since that also
    # parses a hfma chunk, although only the outer version and not the inner one.
    metadata = {}
    expect(hfma_bytes[:4], b"hfma", "not a hfma chunk!")
    byte_length = _unpack_one("<I", hfma_bytes[4:4 + 4])
    expect(byte_length, len(hfma_bytes), "hfma section length mismatch!")
    metadata["byte_length"] = byte_length
    #
    library_file_data = {}
    file_size = _unpack_one("<I", hfma_bytes[8:8 + 4])
    if file_size != 0:
        library_file_data["library_raw_data_size"] = file_size
    library_file_data["file_format_major_version"] = _unpack_one("<H", hfma_bytes[12:12 + 2])
    library_file_data["file_format_minor_version"] = _unpack_one("<H", hfma_bytes[14:14 + 2])
    am_version = hfma_bytes[16:16 + 32].strip(b"\0").decode("ascii")
    library_file_data["apple_music_version_number"] = am_version
    library_id = _bytes_to_id(hfma_bytes[48:48 + 8])
    library_file_data["library_persistent_id"] = library_id
    library_file_data["library_timezone_offset"] = _unpack_one("<I", hfma_bytes[88:88 + 4])
    library_file_data["apple_store_id"] = _unpack_one("<I", hfma_bytes[92:92 + 4])
    library_file_data["library_modification_date"] = _macos_to_unix(_unpack_one("<I", hfma_bytes[100:100 + 4]))

    repeated_library_id = _bytes_to_id(hfma_bytes[108:108 + 8])
    expect_one_of(repeated_library_id, [library_id, b"\0"*16], "repeated library ID mismatch!")

    return metadata, library_file_data

## plma functions:

def parse_plma(plma_bytes: bytes) -> (dict[str: any], dict[str: any]):
    """Parse an plma (library master data) chunk."""
    metadata = _validated_master_metadata(plma_bytes, b"plma", b"boma")

    library_data = {}
    library_id = _bytes_to_id(plma_bytes[58:58 + 8])
    library_data["library_id"] = library_id

    repeated_library_id = _bytes_to_id(plma_bytes[92:92 + 8])
    expect(repeated_library_id, library_id, "repeated library ID mismatch!")

    return metadata, library_data

## lama functions:

def parse_lama(lama_bytes: bytes) -> (dict[str: any], dict[str: any]):
    metadata = _validated_master_metadata(lama_bytes, b"lama", b"iama")

    albums_data = {}
    albums_data["album_count"] = metadata["iama_sections"]

    return metadata, albums_data

## lAma functions:

def parse_lAma(lAma_bytes: bytes) -> (dict[str: any], dict[str: any]):
    metadata = _validated_master_metadata(lAma_bytes, b"lAma", b"iAma")

    artists_data = {}
    artists_data["artists_count"] = metadata["iAma_sections"]

    return metadata, artists_data

## ltma functions:

def parse_ltma(ltma_bytes: bytes) -> (dict[str: any], dict[str: any]):
    metadata = _validated_master_metadata(ltma_bytes, b"ltma", b"itma")

    tracks_data = {}
    tracks_data["tracks_count"] = metadata["itma_sections"]

    return metadata, tracks_data

## lPma functions:

def parse_lPma(lPma_bytes: bytes) -> (dict[str: any], dict[str: any]):
    metadata = _validated_master_metadata(lPma_bytes, b"lPma", b"lpma")

    playlists_data = {}
    playlists_data["playlists_count"] = metadata["lpma_sections"]

    return metadata, playlists_data


# Container functions:

def _validated_container_metadata(container_bytes: bytes, expected_type: bytes) -> dict[str: any]:
    metadata = {}
    expected_type_str = expected_type.decode("utf-8")
    #
    expect(container_bytes[:4], expected_type, f"not an {expected_type_str} chunk!")
    byte_length = _unpack_one("<I", container_bytes[4:4 + 4])
    expect(byte_length, len(container_bytes), f"{expected_type_str} section length mismatch!")
    metadata["byte_length"] = byte_length
    metadata["section_byte_length"] = _unpack_one("<I", container_bytes[8:8 + 4])
    metadata["boma_sections"] = _unpack_one("<I", container_bytes[12:12 + 4])
    #
    return metadata

## lpma functions:

def parse_lpma(lpma_bytes: bytes) -> (dict[str: any], dict[str: any]):
    """Parse an lpma (playlist data) chunk."""
    metadata = _validated_container_metadata(lpma_bytes, b"lpma")

    playlist_data = {}
    playlist_data["track_count"] = _unpack_one("<I", lpma_bytes[16:16 + 4])
    playlist_data["date_created"] = _macos_to_unix(_unpack_one("<I", lpma_bytes[22:22 + 4]))
    playlist_id = _bytes_to_id(lpma_bytes[30:30 + 8])
    playlist_data["playlist_id"] = playlist_id
    playlist_data["date_modified"] = _macos_to_unix(_unpack_one("<I", lpma_bytes[138:138 + 4]))
    playlist_data["?date_unknown"] = _macos_to_unix(_unpack_one("<I", lpma_bytes[182:182 + 4]))

    playlist_repeated_id = _bytes_to_id(lpma_bytes[280:280 + 8])
    playlist_data["playlist_id_repeated"] = playlist_repeated_id

    return metadata, playlist_data


## iAma functions:

def parse_iAma(iAma_bytes: bytes) -> (dict[str: any], dict[str: any]):
    """Parse an iAma (artist data) chunk."""
    metadata = _validated_container_metadata(iAma_bytes, b"iAma")

    artist_data = {}
    artist_id = _bytes_to_id(iAma_bytes[16:16 + 8])
    artist_data["artist_id"] = artist_id

    return metadata, artist_data


## iama functions:

def parse_iama(iama_bytes: bytes) -> (dict[str: any], dict[str: any]):
    """Parse an iama (album data) chunk."""
    metadata = _validated_container_metadata(iama_bytes, b"iama")

    album_data = {}
    album_id = _bytes_to_id(iama_bytes[16:16 + 8])
    album_data["album_id"] = album_id

    return metadata, album_data


def hide_known_iama(iama_bytes: bytes) -> bytes:
    b = list(iama_bytes)

    b[4:4 + 4] = b"\0"*4
    b[8:8 + 4] = b"\0"*4
    b[12:12 + 4] = b"\0"*4
    b[16:16 + 8] = b"\0"*8

    return bytes(b)

## itma functions:

def parse_itma(itma_bytes: bytes) -> (dict[str: any], dict[str: any]):
    """Parse an itma (track data) chunk."""
    metadata = _validated_container_metadata(itma_bytes, b"itma")

    track_data = {}
    persistent_id = _bytes_to_id(itma_bytes[16:16 + 8])
    track_data["track_persistent_id"] = persistent_id

    track_data["skip_when_shuffling"] = _unpack_one("<B", itma_bytes[30:30 + 1]) == 1
    track_data["album_is_compilation"] = _unpack_one("<B", itma_bytes[38:38 + 1]) == 1
    track_data["disabled"] = _unpack_one("<B", itma_bytes[42:42 + 1]) == 1
    track_data["remember_playback_position"] = _unpack_one("<B", itma_bytes[50:50 + 1]) == 1
    track_data["purchased"] = _unpack_one("<B", itma_bytes[58:58 + 1]) == 1
    track_data["content_rating"] = _content_rating_flag_to_value(_unpack_one("<B", itma_bytes[59:59 + 1]))
    track_data["suggestion_flag"] = _unpack_one("<B", itma_bytes[62:62 + 1])  # 3=suggest less. 0=default. 1=undo suggest less.
    track_data["rating"] = _unpack_one("<B", itma_bytes[65:65 + 1])  # stars = rating // 20
    track_data["bpm"] = _unpack_one("<H", itma_bytes[82:82 + 2])
    track_data["disc_n"] = _unpack_one("<H", itma_bytes[84:84 + 2])
    track_data["movement_count"] = _unpack_one("<H", itma_bytes[86:86 + 2])
    track_data["movement_n"] = _unpack_one("<H", itma_bytes[88:88 + 2])
    track_data["disc_count"] = _unpack_one("<H", itma_bytes[90:90 + 2])
    track_data["volume_adjustment_percent"] = _volume_int_to_percent(_unpack_one("<i", itma_bytes[92:92 + 4]))
    track_data["track_count"] = _unpack_one("<H", itma_bytes[116:116 + 2])
    track_data["start_pos_msec"] = _unpack_one("<I", itma_bytes[148:148 + 4])
    track_data["stop_pos_msec"] = _unpack_one("<I", itma_bytes[152:152 + 4])
    track_data["track_n"] = _unpack_one("<H", itma_bytes[160:160 + 2])
    track_data["track_year"] = _unpack_one("<I", itma_bytes[168:168 + 4])
    track_data["album_id"] = _bytes_to_id(itma_bytes[172:172 + 8])
    track_data["artist_id"] = _bytes_to_id(itma_bytes[180:180 + 8])
    repeated_persistent_id = _bytes_to_id(itma_bytes[272:272 + 8])
    expect_one_of(repeated_persistent_id, [persistent_id, "0"*16], "repeated persistent ID mismatch!")
    track_data["date_suggestion_flag_changed"] = _macos_to_unix(_unpack_one("<I", itma_bytes[336:336 + 4]))

    return metadata, track_data


def hide_known_itma(itma_bytes: bytes) -> bytes:
    b = list(itma_bytes)
    b[4:4+4] = b"\0"*4
    b[8:8+4] = b"\0"*4
    b[12:12+4] = b"\0"*4
    b[16:16+8] = b"\0"*8
    b[30:30+1] = b"\0"*1
    b[38:38+1] = b"\0"*1
    b[42:42+1] = b"\0"*1
    b[50:50+1] = b"\0"*1
    b[58:58+1] = b"\0"*1
    b[59:59+1] = b"\0"*1
    b[62:62+1] = b"\0"*1
    b[65:65+1] = b"\0"*1
    b[82:82+2] = b"\0"*2
    b[84:84+2] = b"\0"*2
    b[86:86+2] = b"\0"*2
    b[88:88+2] = b"\0"*2
    b[90:90+2] = b"\0"*2
    b[92:92+4] = b"\0"*4
    b[116:116+2] = b"\0"*2
    b[148:148+4] = b"\0"*4
    b[152:152+4] = b"\0"*4
    b[160:160+2] = b"\0"*2
    b[168:168+4] = b"\0"*4
    b[172:172+8] = b"\0"*8
    b[180:180+8] = b"\0"*8
    b[272:272+8] = b"\0"*8
    b[336:336+8] = b"\0"*8
    return bytes(b)


# boma functions:

# boma subtype functions:

def _get_boma_subtype(boma_bytes: bytes) -> int:
    return _unpack_one("<I", boma_bytes[12:12 + 4])


def _validated_boma_metadata(boma_bytes: bytes, expected_subtypes: list[int] | None) -> dict[str: any]:
    metadata = {}
    # Check chunk type:
    expect(boma_bytes[:4], b"boma", "Not a boma chunk!")
    # Check length:
    byte_length = _unpack_one("<I", boma_bytes[8:8 + 4])
    expect(byte_length, len(boma_bytes), "boma section length mismatch!")
    metadata["byte_length"] = byte_length
    # Get subtype:
    boma_subtype =_get_boma_subtype(boma_bytes)
    metadata["boma_subtype"] = boma_subtype
    if expected_subtypes is not None:
        expect_one_of(boma_subtype, expected_subtypes, "incorrect boma subtype!")
    #
    return metadata


def parse_boma_utf(boma_bytes: bytes) -> (dict[str: any], dict[str: any]):
    track_data = {}
    # Get metadata:
    metadata = _validated_boma_metadata(boma_bytes, list(BOMA_UTF_SUBTYPES.keys()))
    # Get encoding:
    encoding_int = _unpack_one("<I", boma_bytes[20:20 + 4])
    expect_one_of(encoding_int, [1, 2], "unexpected encoding!")
    encoding = {1: "utf-16", 2: "utf-8"}[encoding_int]
    # Check string data length:
    string_byte_len = _unpack_one("<I", boma_bytes[24:24 + 4])
    expect(string_byte_len + 36, metadata["byte_length"], "string byte length mismatch!")
    # Get string value:
    track_property_name = BOMA_UTF_SUBTYPES[metadata["boma_subtype"]]
    track_property_string_value = boma_bytes[36:].decode(encoding)
    track_data[track_property_name] = track_property_string_value

    return metadata, track_data


def parse_boma_short_utf(boma_bytes: bytes, encoding: str) -> (dict[str: any], dict[str: any]):
    data = {}
    # Get metadata:
    metadata = _validated_boma_metadata(boma_bytes, list(BOMA_SHORT_UTF8_SUBTYPES.keys()) + list(BOMA_SHORT_UTF16_SUBTYPES.keys()))
    # Get string value:
    property_name = BOMA_SHORT_UTF8_SUBTYPES.get(metadata["boma_subtype"]) or BOMA_SHORT_UTF16_SUBTYPES.get(metadata["boma_subtype"])
    property_string_value = boma_bytes[20:].decode(encoding)
    data[property_name] = property_string_value

    return metadata, data


def parse_boma_s1(boma_bytes: bytes) -> (dict[str: any], dict[str: any]):
    """Parse boma subtype 0x01."""
    # Check metadata:
    metadata = _validated_boma_metadata(boma_bytes, [1])
    # Extract data:
    track_data = {}
    track_data["sample_rate"] = int(_unpack_one("<f", boma_bytes[80:80 + 4]))  # stored as float, but should be int
    track_data["file_folder_count"] = _unpack_one("<H", boma_bytes[92:92 + 2])
    track_data["library_folder_count"] = _unpack_one("<H", boma_bytes[94:94 + 2])
    track_data["bit_rate"] = _unpack_one("<I", boma_bytes[108:108 + 4])
    track_data["date_added"] = _macos_to_unix(_unpack_one("<I", boma_bytes[112:112 + 4]))
    track_data["date_modified"] = _macos_to_unix(_unpack_one("<I", boma_bytes[148:148 + 4]))
    track_data["purchase_date"] = _macos_to_unix(_unpack_one("<I", boma_bytes[156:156 + 4]))
    track_data["release_date"] = _macos_to_unix(_unpack_one("<I", boma_bytes[160:160 + 4]))
    track_data["total_time"] = _unpack_one("<I", boma_bytes[176:176 + 4])
    track_data["size"] = _unpack_one("<I", boma_bytes[316:316 + 4])

    return metadata, track_data


def hide_known_boma_s1(boma_bytes: bytes) -> bytes:
    """
    Blank out known byte sections of boma subtype 1 chunk to simplify diffs.
    """
    b = list(boma_bytes)
    b[8:8+4] = b"\0"*4
    b[80:80+4] = b"\0"*4
    b[92:92+2] = b"\0"*2
    b[94:94+2] = b"\0"*2
    b[108:108+4] = b"\0"*4
    b[112:112+4] = b"\0"*4
    b[148:148+4] = b"\0"*4
    b[156:156+4] = b"\0"*4
    b[160:160+4] = b"\0"*4
    b[176:176+4] = b"\0"*4
    b[316:316+4] = b"\0"*4
    return bytes(b)


def parse_boma_s23(boma_bytes: bytes) -> (dict[str: any], dict[str: any]):
    """Parse boma subtype 0x17."""
    # Check metadata:
    metadata = _validated_boma_metadata(boma_bytes, [23])
    # Extract data:
    track_data = {}
    track_data["play_date"] = _macos_to_unix(_unpack_one("<I", boma_bytes[28:28 + 4]))
    track_data["play_count_1"] = _unpack_one("<I", boma_bytes[32:32 + 4])
    track_data["play_count_2"] = _unpack_one("<I", boma_bytes[36:36 + 4])
    track_data["skip_date"] = _macos_to_unix(_unpack_one("<I", boma_bytes[48:48 + 4]))
    track_data["skip_count_1"] = _unpack_one("<I", boma_bytes[52:52 + 4])
    track_data["skip_count_2"] = _unpack_one("<I", boma_bytes[56:56 + 4])

    return metadata, track_data


def parse_boma_s36(boma_bytes: bytes) -> (dict[str: any], dict[str: any]):
    """Parse boma subtype 0x24."""
    # Check metadata:
    metadata = _validated_boma_metadata(boma_bytes, [36])
    # Extract data:
    track_data = {}
    track_data["video_height"] = _unpack_one("<I", boma_bytes[20:20 + 4])
    track_data["video_width"] = _unpack_one("<I", boma_bytes[24:24 + 4])
    track_data["frame_rate"] = _unpack_one("<I", boma_bytes[64:64 + 4]) / 1000

    return metadata, track_data


def parse_boma_s206(boma_bytes: bytes) -> (dict[str: any], dict[str: any]):
    """Parse boma subtype 0xCE."""
    # Check metadata:
    metadata = _validated_boma_metadata(boma_bytes, [206])
    expect(boma_bytes[20:20 + 4], b"ipfa", "expected an ipfa chunk inside!")
    # Extract data:
    playlist_track_data = {}
    ipfa_id =  _bytes_to_id(boma_bytes[32:32 + 8])
    playlist_track_data["ipfa_id"] = ipfa_id
    playlist_track_data["track_id"] = _bytes_to_id(boma_bytes[40:40 + 8])

    repeated_ipfa_id = _bytes_to_id(boma_bytes[64:64 + 8])
    expect_one_of(repeated_ipfa_id, [ipfa_id, "0"*16], "expected repeated ipfa ID!")

    return metadata, {"tracks": [playlist_track_data]}


def hide_known_boma_s206(boma_bytes: bytes) -> bytes:
    b = list(boma_bytes)
    b[8:8+4] = b"\0"*4
    b[20:20+4] = b"\0"*4
    b[24:24+4] = b"\0"*4
    b[32:32+8] = b"\0"*8
    b[40:40+8] = b"\0"*8
    b[64:64+8] = b"\0"*8
    return bytes(b)

## boma meta-function

def parse_boma(boma_bytes: bytes) -> (dict[str: any], dict[str: any]):
    metadata = _validated_boma_metadata(boma_bytes, None)
    subtype = metadata["boma_subtype"]
    # Parse the boma bytes using the correct subtype method:
    if subtype == 1:
        return parse_boma_s1(boma_bytes)
    elif subtype in BOMA_UTF_SUBTYPES:
        return parse_boma_utf(boma_bytes)
    elif subtype in BOMA_SHORT_UTF8_SUBTYPES:
        return parse_boma_short_utf(boma_bytes, "utf-8")
    elif subtype in BOMA_SHORT_UTF16_SUBTYPES:
        return parse_boma_short_utf(boma_bytes, "utf-16")
    elif subtype == 23:
        return parse_boma_s23(boma_bytes)
    elif subtype == 36:
        return parse_boma_s36(boma_bytes)
    elif subtype == 206:
        return parse_boma_s206(boma_bytes)
    elif subtype in BOMA_IGNORE_SUBTYES.keys():
        return metadata, {}
    else:
        # Unknown subtype, return no parsed data:
        return metadata, None
