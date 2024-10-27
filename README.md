# musicdb-to-json

This script will parse an Apple Music `Library.musicdb` file and convert it to JSON data with similar
properties to the XML export supported by iTunes on Windows or Apple Music on MacOS. This is useful
because Apple Music on Windows no longer supports any form of library export.

The `musicdb` file format is undocumented and partially encrypted using a secret key, the same key as the `itl` file format.
A copy of the key is required to use this code. The key has been published in several similar projects
on GitHub, but is not included here.

## Usage

Requires Python 3.12 or later. Either clone the repo or download the files, then install the dependencies: 

```shell
pip install -r requirements.txt
```

The script can then be run as:

```shell
python musicdb_to_json.py --decryption-key="SECRET-KEY-HERE" Library.musicdb
```
which will parse the library file and output `library.json` containing track, artist, album and
playlist data. JSON key names aim to be consistent with the iTunes XML key names, except in `snake_case` format.
Sadly the XML "Track ID" property does not seem to be present in the musicdb file, but the "Persistent ID"s are
the same in this JSON the standard XML exports.

Further arguments are provided to output to a different filename or to output the raw decrypted
and decompressed bytes for further investigation.

The script is opinionated about the file format and will error on unexpected values or format.
Please open an issue if you can't fix it yourself!

## Acknowledgements

This project builds heavily on the prior work of others: https://home.vollink.com/gary/playlister/musicdb.html. 
Most of the details of the byte ranges and meanings come from that page!

The script is based on a complete rewrite of rinsuki's [musicdb2sqlite](https://github.com/rinsuki/musicdb2sqlite) tool.

## Similar Projects

As mentioned, [musicdb2sqlite](https://github.com/rinsuki/musicdb2sqlite) is a similar project that 
will convert a `musicdb` file to an SQLite database, which can then dump to JSON or XML.

For iTunes `.itl` file parsing there exist older projects:
 - [titl](https://github.com/josephw/titl), which allows reading and modification of `itl` files.
 - Another script [extracts playlists from `itl` files](https://gist.github.com/jeamland/c856e9993008c9611a9910a3b22f9479).
 - [A project in Go](https://github.com/rclancey/itunes) to extract data from the XML and `itl` files.
