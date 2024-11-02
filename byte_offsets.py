from collections.abc import Callable
from typing import Optional, Literal

from utilities import _bytes_to_id, _is_one, _content_rating_flag_to_value, _volume_int_to_percent, _macos_to_unix, \
    _version_bytes_to_str

type ByteFormatSpecifier = str | int
type OptionalConversionFunction = Optional[Callable[[bytes], any]]
type MetadataStr = Literal["metadata"]
# Each useful line below will be a ByteDetail indicating the offset, name, format/length and conversion for byte values:
type ByteDetail = tuple[int, str, ByteFormatSpecifier, OptionalConversionFunction]
type ByteDetails = list[ByteDetail]
type ContainerByteDetailMap = dict[bytes | MetadataStr, ByteDetails]
type BomaByteDetailMap = dict[int | MetadataStr, ByteDetails]


HFMA_BYTE_DETAILS: ContainerByteDetailMap = {
    "metadata": [
        (0, "chunk_type", 4, None),
        (4, "byte_length", "I", None),
    ],
    b"hfma": [
        ( 8, "library_raw_data_size", "I", lambda x: x if x != 0 else None),  # discard if incorrectly 0
        (12, "file_format_major_version", "H", None),
        (14, "file_format_minor_version", "H", None),
        (16, "apple_music_version_number", 32, _version_bytes_to_str),
        (48, "library_persistent_id", 8, _bytes_to_id),
        (88, "library_timezone_offset", "I", None),
        (92, "apple_store_id", "I", None),
        (100, "library_modification_date", "I", _macos_to_unix),
        (108, "_library_persistent_id_repeated", 8, _bytes_to_id),
    ]
}


MASTER_BYTE_DETAILS: ContainerByteDetailMap = {
    "metadata": [
        (0, "chunk_type", 4, None),
        (4, "byte_length", "I", None),
        (8, "container_sections", "I", None),
    ],
    b"plma": [
        (58, "library_id", 8, _bytes_to_id),
        (92, "_library_id_repeated", 8, _bytes_to_id),
    ]
}


CONTAINER_BYTE_DETAILS: ContainerByteDetailMap = {
    "metadata": [
        ( 0, "chunk_type", 4, None),
        ( 4, "byte_length", "I", None),
        ( 8, "section_byte_length", "I", None),
        (12, "boma_sections", "I", None),
    ],
    b"iama": [
        (16, "album_id", 8, _bytes_to_id),
    ],
    b"iAma": [
        (16, "artist_id", 8, _bytes_to_id),
    ],
    b"itma": [
        ( 16, "track_persistent_id", 8, _bytes_to_id),
        ( 30, "skip_when_shuffling", "B", _is_one),
        ( 38, "album_is_compilation", "B", _is_one),
        ( 42, "disabled", "B", _is_one),
        ( 50, "remember_playback_position", "B", _is_one),
        ( 58, "purchased", "B", _is_one),
        ( 59, "content_rating", "B", _content_rating_flag_to_value),
        ( 62, "suggestion_flag", "B", None),  # 3=suggest less. 0=default. 1=undo suggest less.
        ( 65, "rating", "B", None),  # stars = rating // 20
        ( 82, "bpm", "H", None),
        ( 84, "disc_n", "H", None),
        ( 86, "movement_count", "H", None),
        ( 88, "movement_number", "H", None),
        ( 90, "disc_count", "H", None),
        ( 92, "volume_adjustment_percent", "i", _volume_int_to_percent),
        (116, "track_count", "H", None),
        (148, "start_pos_msec", "I", None),
        (152, "stop_pos_msec", "I", None),
        (160, "track_number", "H", None),
        (168, "track_year", "I", None),
        (172, "album_id", 8, _bytes_to_id),
        (180, "artist_id", 8, _bytes_to_id),
        (272, "_persistent_id_repeated", 8, _bytes_to_id),
        (336, "date_suggestion_flag_changed", "I", _macos_to_unix),
    ],
    b"lpma": [
        ( 16, "track_count", "I", None),
        ( 22, "date_created", "I", _macos_to_unix),
        ( 30, "playlist_id", 8, _bytes_to_id),
        (138, "date_modified", "I", _macos_to_unix),
        (182, "date_unknown", "I", _macos_to_unix),
        (280, "_playlist_id_repeated", 8, _bytes_to_id),
    ],
}


BOMA_SUBTYPE_BYTE_DETAILS: BomaByteDetailMap = {
    "metadata": [
        ( 0, "chunk_type", 4, None),
        ( 8, "byte_length", "I", None),
        (12, "boma_subtype", "I", None),
    ],
    1: [  # 0x1
        ( 80, "sample_rate", "f", lambda x: int(x)),  # stored as float, but should be int
        ( 92, "file_folder_count", "H", None),
        ( 94, "library_folder_count", "H", None),
        (108, "bit_rate", "I", None),
        (112, "date_added", "I", _macos_to_unix),
        (148, "date_modified", "I", _macos_to_unix),
        (152, "?normalisation", "I", None),
        (156, "purchase_date", "I", _macos_to_unix),
        (160, "release_date", "I", _macos_to_unix),
        (176, "total_time", "I", None),
        (316, "size", "I", None),
    ],
    23: [  # 0x17
        (28, "play_date", "I", _macos_to_unix),
        (32, "play_count_1", "I", None),
        (36, "play_count_2", "I", None),
        (48, "skip_date", "I", _macos_to_unix),
        (52, "skip_count_1", "I", None),
        (56, "skip_count_2", "I", None),
    ],
    36: [  # 0x24
        (20, "video_height", "I", None),
        (24, "video_width", "I", None),
        (64, "frame_rate", "I", lambda x: x / 1000),
    ],
}
