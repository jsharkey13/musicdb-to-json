import struct
import zlib
from io import BytesIO

from Crypto.Cipher import AES

from byte_offsets import BOMA_SUBTYPE_BYTE_DETAILS, ByteDetails, CONTAINER_BYTE_DETAILS, HFMA_BYTE_DETAILS, \
    MASTER_BYTE_DETAILS
from utilities import expect, _unpack_one, _bytes_to_id, expect_one_of

# See https://home.vollink.com/gary/playlister/musicdb.html
# for a detailed analysis, and the source of much of the byte offset
# and data interpretations in the parse functions.
# See # https://github.com/rinsuki/musicdb2sqlite for the inspiration
# for this script and library.

ENDIANNESS = "<"

MASTER_CONTAINER_TYPES = {
    b"plma": (b"boma", "boma"),  # This one isn't really like the others!
    b"lama": (b"iama", "album"),
    b"lAma": (b"iAma", "artist"),
    b"ltma": (b"itma", "track"),
    b"lPma": (b"lpma", "playlist"),
}

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
    0x200: "media_folder",  # library
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
    0x42:  "?track_filename_book_boma",
    0xC9:  "?smart_playlist_settings",
    0xCA:  "?unknown_playlist_boma",
    0xCD:  "generated_artwork_uuids_plist",
    0x192: "artwork_url_plist",
    0x1F6: "?unknown_lpma_boma",
    0x1FD: "?media_folder_book_boma",
    0x1FF: "?unknown_lpma_boma",
}


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

# Byte-offset processing functions:

def _extract_byte_data(chunk_bytes: bytes, byte_details: ByteDetails) -> dict[str, any]:
    data = {}
    for byte_offset, key_name, format_specifier, conversion_function in byte_details:
        range_length = format_specifier if type(format_specifier) is int else struct.calcsize(format_specifier)
        range_bytes = chunk_bytes[byte_offset: byte_offset + range_length]
        # Unpack the bytes if necessary:
        if type(format_specifier) is not int:
            raw_value = _unpack_one(f"{ENDIANNESS}{format_specifier}", range_bytes)
        else:
            raw_value = range_bytes
        # Convert the raw value if necessary:
        value = raw_value
        if conversion_function is not None:
            converted = conversion_function(raw_value)
            if converted is None:
                # Exclude value entirely if result of conversion is None!
                continue
            value = converted
        #
        data[key_name] = value
    return data


def hide_known_byte_details(chunk_bytes: bytes, byte_details: ByteDetails) -> bytes:
    """
    Zero out known byte regions of a chunk to aid further decoding work.

    E.g. to show the unknown parts of an itma chunk in hex:
        print(hide_known_byte_details(itma_bytes, CONTAINER_BYTE_DETAILS[b"itma"]).hex())
    """
    b = list(chunk_bytes)
    for byte_offset, _, format_specifier, _ in byte_details:
        range_length = format_specifier if type(format_specifier) is int else struct.calcsize(format_specifier)
        b[byte_offset:byte_offset+range_length] = b"\0" * range_length
    return bytes(b)


# Section master functions:

def _validated_master_metadata(master_bytes: bytes) -> dict[str: any]:
    metadata = _extract_byte_data(master_bytes, MASTER_BYTE_DETAILS["metadata"])
    #
    expect_one_of(metadata["chunk_type"], list(MASTER_CONTAINER_TYPES.keys()), f"not a master chunk!")
    expect(metadata["byte_length"], len(master_bytes), f"master chunk length mismatch!")

    subtype = MASTER_CONTAINER_TYPES[metadata["chunk_type"]][0].decode("utf-8")
    metadata[f"{subtype}_sections"] = metadata["container_sections"]

    return metadata


def parse_master(master_bytes: bytes) -> (dict[str: any], dict[str: any]):
    metadata = _validated_master_metadata(master_bytes)

    data = {}
    master_type = MASTER_CONTAINER_TYPES[metadata["chunk_type"]][1]
    if master_type != "boma":
        data[f"{master_type}_count"] = metadata["container_sections"]

    return metadata, data


## hfma functions:

def parse_hfma(hfma_bytes: bytes) -> (dict[str: any], dict[str: any]):
    # Some of this will duplicate behaviour in get_library_bytes since that also
    # parses a hfma chunk, although only the outer version and not the inner one.
    metadata = _extract_byte_data(hfma_bytes, HFMA_BYTE_DETAILS["metadata"])
    expect(metadata["chunk_type"], b"hfma", "not a hfma chunk!")
    expect(metadata["byte_length"], len(hfma_bytes), "hfma section length mismatch!")
    #
    library_file_data = _extract_byte_data(hfma_bytes, HFMA_BYTE_DETAILS[metadata["chunk_type"]])

    return metadata, library_file_data


# Container functions:

def _validated_container_metadata(container_bytes: bytes, expected_type: bytes) -> dict[str: any]:
    metadata = _extract_byte_data(container_bytes, CONTAINER_BYTE_DETAILS["metadata"])
    # Validate:
    expect(metadata["chunk_type"], expected_type, "unexpected container type!")
    expect_one_of(metadata["chunk_type"], list(CONTAINER_BYTE_DETAILS.keys()), "not a container chunk!")
    expect(metadata["byte_length"], len(container_bytes), "container chunk length mismatch!")
    # Return:
    return metadata


def parse_container(container_bytes: bytes, expected_type: bytes) -> (dict[str: any], dict[str: any]):
    metadata = _validated_container_metadata(container_bytes, expected_type)
    data = _extract_byte_data(container_bytes, CONTAINER_BYTE_DETAILS[metadata["chunk_type"]])
    return metadata, data


# boma functions:

## boma subtype functions:

def _get_boma_subtype(boma_bytes: bytes) -> int:
    return _unpack_one("<I", boma_bytes[12:12 + 4])


def _validated_boma_metadata(boma_bytes: bytes, expected_subtypes: list[int] | None) -> dict[str: any]:
    metadata = _extract_byte_data(boma_bytes, BOMA_SUBTYPE_BYTE_DETAILS["metadata"])
    # Validate:
    expect(metadata["chunk_type"], b"boma", "Not a boma chunk!")
    expect(metadata["byte_length"], len(boma_bytes), "boma section length mismatch!")
    if expected_subtypes is not None:
        expect_one_of(metadata["boma_subtype"], expected_subtypes, "incorrect boma subtype!")
    # Return:
    return metadata


def parse_boma_by_byte_detail(boma_bytes: bytes) -> (dict[str: any], dict[str: any]):
    metadata = _validated_boma_metadata(boma_bytes, list(BOMA_SUBTYPE_BYTE_DETAILS.keys()))
    data = _extract_byte_data(boma_bytes, BOMA_SUBTYPE_BYTE_DETAILS[metadata["boma_subtype"]])
    return metadata, data


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


def parse_boma_s206(boma_bytes: bytes) -> (dict[str: any], dict[str: any]):
    """
    Parse boma subtype 0xCE.

    This subtype contains further regions, and the inner data is not a direct property of the parent
    but another item to be added to a list inside the parent.
    """
    # Check metadata:
    metadata = _validated_boma_metadata(boma_bytes, [206])
    expect(boma_bytes[20:20 + 4], b"ipfa", "expected an ipfa chunk inside!")
    # Extract data:
    playlist_track_data = {}
    ipfa_id =  _bytes_to_id(boma_bytes[32:32 + 8])
    playlist_track_data["ipfa_id"] = ipfa_id
    playlist_track_data["track_id"] = _bytes_to_id(boma_bytes[40:40 + 8])

    repeated_ipfa_id = _bytes_to_id(boma_bytes[64:64 + 8])
    expect_one_of(repeated_ipfa_id, [ipfa_id, None], "expected repeated ipfa ID!")

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
    if subtype in BOMA_SUBTYPE_BYTE_DETAILS:
        return parse_boma_by_byte_detail(boma_bytes)
    elif subtype in BOMA_UTF_SUBTYPES:
        return parse_boma_utf(boma_bytes)
    elif subtype in BOMA_SHORT_UTF8_SUBTYPES:
        return parse_boma_short_utf(boma_bytes, "utf-8")
    elif subtype in BOMA_SHORT_UTF16_SUBTYPES:
        return parse_boma_short_utf(boma_bytes, "utf-16")
    elif subtype == 206:
        return parse_boma_s206(boma_bytes)
    elif subtype in BOMA_IGNORE_SUBTYES.keys():
        return metadata, {}
    else:
        # Unknown subtype, return no parsed data:
        return metadata, None
