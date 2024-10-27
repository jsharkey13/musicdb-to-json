import argparse
import io
import json

from musicdb import get_library_bytes, merge_in, parse_boma, parse_hfma, parse_iama, parse_iAma, parse_itma, parse_lama, \
    parse_lAma, parse_lpma, parse_lPma, parse_ltma, parse_plma, read_next_chunk

# See # https://github.com/rinsuki/musicdb2sqlite for the inspiration
# for this script and library.

# Script arguments:

parser = argparse.ArgumentParser(
    description='Convert an Apple Music musicdb file to JSON. '
                'This project assumes a Little-Endian library storage format!',
    epilog="The decryption key is required but not included."
)

parser.add_argument('musicdb_file', help="The musicdb library file to convert.")
parser.add_argument('--output-file', '-o',
                    help="The file to write the JSON output to, or 'library.json' if not provided.",
                    default="library.json")
parser.add_argument('--raw-bytes-file',
                    help="If provided, write the raw decrypted and decompressed bytes to this file.")
parser.add_argument('--decryption-key',
                    help='The iTunes/Apple Music library AES key, as text ("BHU.............").',
                    required=True)

args = vars(parser.parse_args())

# Process the library:
library = {}

library_bytes = get_library_bytes(args["musicdb_file"], args["decryption_key"])

# Use a BytesIO object to maintain position in file:
library_bytestream = io.BytesIO(library_bytes)

while library_bytestream.readable():
    r = read_next_chunk(library_bytestream)
    if r is None:
        break
    chunk_type, chunk_bytes = r

    if chunk_type == b"hsma":
        # Separator chunk!
        continue

    # Library metadata:
    elif chunk_type == b"hfma":
        hfma_data, library_file_data = parse_hfma(chunk_bytes)

        merge_in(library, library_file_data)

    elif chunk_type == b"plma":
        plma_data, library_data = parse_plma(chunk_bytes)

        subtypes_parsed = set()
        for i in range(plma_data["boma_sections"]):
            _, cb = read_next_chunk(library_bytestream)
            md, ld = parse_boma(cb)

            if md["boma_subtype"] in subtypes_parsed:
                print(f"Duplicate subtype ({md["boma_subtype"]}) for plma section!")
            subtypes_parsed.add(md["boma_subtype"])

            if ld is not None:
                merge_in(library_data, ld)
            else:
                print(f"Unknown subtype ({md["boma_subtype"]}) for plma section!")

        merge_in(library, library_data)

    # Album data:
    elif chunk_type == b"lama":
        lama_data, albums_data = parse_lama(chunk_bytes)

        merge_in(library.setdefault("album_data", {}), albums_data)

    elif chunk_type == b"iama":
        iama_data, album_data = parse_iama(chunk_bytes)

        subtypes_parsed = set()
        for i in range(iama_data["boma_sections"]):
            _, cb = read_next_chunk(library_bytestream)
            md, ad = parse_boma(cb)

            if md["boma_subtype"] in subtypes_parsed:
                print(f"Duplicate subtype ({md["boma_subtype"]}) for {album_data.get("album_id")}!")
            subtypes_parsed.add(md["boma_subtype"])

            if ad is not None:
                merge_in(album_data, ad)
            else:
                print(f"Unknown subtype ({md["boma_subtype"]}) for {album_data.get("album_id")}!")

        library.setdefault("album_data", {}).setdefault("albums", []).append(album_data)

    # Artist data:
    elif chunk_type == b"lAma":
        lAma_data, artists_data = parse_lAma(chunk_bytes)

        merge_in(library.setdefault("artist_data", {}), artists_data)

    elif chunk_type == b"iAma":
        iAma_data, artist_data = parse_iAma(chunk_bytes)

        subtypes_parsed = set()
        for i in range(iAma_data["boma_sections"]):
            _, cb = read_next_chunk(library_bytestream)
            md, artd = parse_boma(cb)

            if md["boma_subtype"] in subtypes_parsed:
                print(f"Duplicate subtype ({md["boma_subtype"]}) for {artist_data.get("album_id")}!")
            subtypes_parsed.add(md["boma_subtype"])

            if artd is not None:
                merge_in(artist_data, artd)
            else:
                print(f"Unknown subtype ({md["boma_subtype"]}) for {artist_data.get("artist_id")}!")

        library.setdefault("artist_data", {}).setdefault("artists", []).append(artist_data)

    # Track data:
    elif chunk_type == b"ltma":
        ltma_data, tracks_data = parse_ltma(chunk_bytes)

        merge_in(library.setdefault("track_data", {}), tracks_data)

    elif chunk_type == b"itma":
        itma_data, track_data = parse_itma(chunk_bytes)

        subtypes_parsed = set()
        for i in range(itma_data["boma_sections"]):
            _, cb = read_next_chunk(library_bytestream)
            md, td = parse_boma(cb)

            if md["boma_subtype"] in subtypes_parsed:
                # Duplicate sections seem to contain invalid data? Skip them!
                continue
            subtypes_parsed.add(md["boma_subtype"])

            if td is not None:
                merge_in(track_data, td)
            else:
                print(f"Unknown subtype ({md["boma_subtype"]}) for {track_data.get("track_persistent_id")}!")

        library.setdefault("track_data", {}).setdefault("tracks", []).append(track_data)

    # Playlist data:
    elif chunk_type == b"lPma":
        lPma_data, playlists_data = parse_lPma(chunk_bytes)

        merge_in(library.setdefault("playlist_data", {}), playlists_data)

    elif chunk_type == b"lpma":
        lpma_data, playlist_data = parse_lpma(chunk_bytes)

        for i in range(lpma_data["boma_sections"]):
            _, cb = read_next_chunk(library_bytestream)
            md, pd = parse_boma(cb)

            if pd is not None:
                merge_in(playlist_data, pd)
            else:
                print(f"Unknown subtype ({md["boma_subtype"]}) for {playlist_data.get("playlist_id")}!")

        library.setdefault("playlist_data", {}).setdefault("playlists", []).append(playlist_data)

    else:
        print(f"Skipping unexpected chunk: {chunk_type}!")


# Write the raw bytes to file:
if args["raw_bytes_file"]:
    with open(args["raw_bytes_file"], "wb") as content_binary_file:
        content_binary_file.write(library_bytes)

# Write the decoded library data to JSON:
with open(args["output_file"], "w", encoding="utf8") as lf:
    json.dump(library, lf, indent=2)
