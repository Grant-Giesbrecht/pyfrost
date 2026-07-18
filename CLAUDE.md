# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Pyfrost is a Python library (`pyfrost-network` on PyPI, importable as `pyfrost`) providing a TCP client/server
framework for building networked apps: encrypted transport (RSA handshake + AES for the session), account
management backed by SQLite, and a "lobby" abstraction for grouping connected clients. It is one of several
sibling projects by the same author (`jarnsaxa`, `pylogfile`, `stardust`) and is itself consumed by other
projects (e.g. "constellation" — see commit history for cross-repo breakage/fixes).

## Install / environment

This repo is normally developed alongside sibling repos checked out under the same parent directory
(`jarnsaxa`, `pylogfile`, `stardust`), each installed editable (`pip install -e .`). Check with `pip show <pkg>`
before assuming a dependency is missing — it may be installed editable from a sibling checkout rather than PyPI.

```
pip install -e .
```

**`pyproject.toml`'s dependency list is incomplete.** The code actually imports `msgpack`, `colorama`, `PyQt6`,
and `stardust` (both `stardust.cli` and `stardust.serializer`) in addition to the declared
`pylogfile`, `jarnsaxa`, `rsa`, `pycryptodome`, `tabulate`. `stardust` is not published to PyPI — it must be
available as an editable sibling checkout. If you add a new import, also add it to `pyproject.toml`.

There is no test suite, no lint config, and no CI in this repo — don't assume `pytest`/`ruff`/etc. are wired up.

## Running things

- **Server example**: `python examples/ex1_server.py [-l|--local] [--loglevel LEVEL]` — binds a socket and calls
  `server_main()`. Requires a PyQt6 GUI by default (`use_gui=True`); pass `use_gui=False` in code to run headless.
- **GUI server example**: `python examples/ex1gui_server.py` — fuller PyQt6 status window.
- **Client example**: `python examples/ex1_client.py [-l|--local]` — connects and drops into an interactive CLI
  (`commandline_main`).
- **DB init**: `pyfrost-init-db <db_name>` (entry point script, `src/pyfrost/scripts/pyfrost_init_db.py`) —
  interactively creates the `userdata` SQLite table and prompts for the first (admin) account.
- **DB view**: `pyfrost-view-db <db_name>` — dumps the user table via `UserDatabase.view_database()`.

The example server/client hardcode a LAN IP (`192.168.1.116:5555`); use `-l/--local` to bind/connect to
`localhost` instead when testing on one machine.

## Architecture

Three modules under `src/pyfrost/`:

- **`base.py`** — shared primitives used by both client and server. No networking of its own; everything here
  is protocol-agnostic infrastructure:
  - `Packable` — mixin giving classes `pack()`/`unpack()` to/from JSON dicts, driven by three lists
    (`manifest`, `obj_manifest`, `list_manifest`) that a subclass populates in `set_manifest()`. Used for
    `GenData`/`GenCommand`, the message envelope for all client↔server traffic.
  - `GenCommand` / `GenData` — the generic command/response envelope. `GenCommand` carries a `command` string
    plus a `data` dict; `GenData` is the reply, always expected to carry a `STATUS` field. Both serialize via
    `to_utf8()`/`from_utf8()` (JSON). This is the extension point: application code registers new command
    names by inspecting `gc.command` in the `query_func`/`send_func` callbacks passed into `server_main()`.
  - `UserDatabase` — all SQLite access for the `userdata` table (accounts, password hashes, account types).
    Every method acquires the module-level `db_mutex` before touching the DB — treat that mutex as required,
    not optional, when adding new DB methods.
  - `ThreadSafeDict` / `ThreadSafeList` — generic mutex-guarded containers. **Callers must hold `.mtx`
    themselves** before calling most methods; the class does not lock internally (see class docstrings).
  - `LobbyTemplate` — abstract base a host application subclasses to define its own "lobby" (game room, chat
    room, etc.); must implement `client_count()`, `add_user()`, `remove_user()` and be `Serializable`
    (from `stardust.serializer`).
  - `Message`, `SyncData` — `Serializable` (stardust) payloads used for the notification/sync system (see below).

- **`pf_server.py`** — the `ServerAgent` (one `threading.Thread` per connected client) and `server_main()`/
  `server_main_loop()`. Key points:
  - Per-connection state machine: `TS_HAND` (RSA/AES handshake) → `TS_LOGIN` (auth) → `TS_MAIN` (authenticated,
    handling `SENDGC`/`QRYGC`/`SYNC`/etc.) → `TS_EXIT`.
  - Handshake: server sends RSA pubkey, client sends its own back, then an AES key+IV is exchanged over RSA;
    all further traffic is AES-CBC with a length-prefixed framing (`send()`/`recv()` in both `pf_server.py`
    and `pf_client.py` implement the same framing — keep them in sync if you touch one).
  - Built-in `GenCommand`s handled directly in `execute_sendgc`/`execute_querygc`: `MSGUSR`, `JOINLOBBY`,
    `LEAVELOBBY`, `NUMUSER`, `NEWLOBBY`. Anything else falls through to the user-supplied `send_func`/
    `query_func` callbacks passed into `server_main()` — this is how a host application adds its own commands
    without forking pyfrost.
  - Global, mutex-protected shared state (module-level): `lobby_objects`/`lobby_locks`/`lobby_master_lock`
    (all active lobbies), `user_directory`/`directory_mutex` (username → list of `DirectoryEntry`, one per
    logged-in connection, so a user can have multiple simultaneous connections), `distribution_inbox`/
    `distribution_mutex` (pending `Message`s awaiting delivery). Three background threads manage these:
    `garbage_collect_thread_main` (drops lobbies with `client_count() == 0`), `distribution_thread_main`
    (drains `distribution_inbox` into each recipient's per-connection note list), `server_stat_thread_main`
    (periodic console/GUI stats). When touching this shared state, always acquire the matching lock — the
    lock/data pairs are parallel lists (`lobby_objects[i]` ↔ `lobby_locks[i]`), so keep them structurally in
    sync (see the `#TODO`s in `garbage_collect_thread_main` about this being fragile at scale).
  - `SYNC` command (`get_syncdata()`) is how the server pushes lobby state + queued notes + connection_state to
    a client, serialized with `stardust`'s `to_serial_dict`/`from_serial_dict` and packed with `msgpack` (not
    the AES-framed JSON path used elsewhere — `SYNC` payloads are binary msgpack).
  - Optional PyQt6 GUI (`PyfrostServerGUI`/`StatsWidget`) is always imported at module level even when
    `use_gui=False` is passed to `server_main()` — importing `pf_server` requires PyQt6 to be installed
    regardless of whether the GUI is actually used.

- **`pf_client.py`** — `ClientAgent` mirrors the server's handshake/encryption and exposes methods
  (`login`, `create_account`, `logout`, `send_command`/`query_command`, `sync`, `message_user`, `num_user`,
  `view_database`, `delete_account`, `shutdown_server`, `exit`) that speak the same wire protocol as
  `ServerAgent`. `commandline_main()` is a ready-made interactive REPL built on top of `ClientAgent`; host
  applications extend it via the `commandline_extended` callback (signature
  `(ca, words) -> (found:bool, autosync_eligible:bool)`), following the pattern in `examples/ex1_client.py`.
  Client-side settings (e.g. `autosync-post-command`) are managed through `stardust.cli.SettingsCLI`
  (`ClientAgent.settings_manager`), exposed to the user via the `CLIENTSETTINGS` REPL command.
  Command-line help text is data-driven from JSON files (`help_source`/`topic_source` constructor args,
  see `examples/help.json` and `examples/topic_help.json`) rather than hardcoded — new commands should get
  entries there for the `HELP`/`TOPICS` REPL commands to pick them up.

## Extending pyfrost for a host application

The intended integration pattern (see `examples/ex1_server.py` + `examples/ex1_client.py`):
1. Define new `GenCommand` names and handle them via `query_func` (expects a `GenData` reply) or `send_func`
   (fire-and-forget, returns bool) passed into `server_main()`.
2. On the client, extend the REPL via `commandline_extended` passed into `commandline_main()`, and/or call
   `ClientAgent.send_command`/`query_command` directly from application code.
3. Subclass `LobbyTemplate` (must also be `Serializable`) for any per-room shared state; wire it up via the
   `lobby_generator` callable passed into `server_main()` (invoked on `NEWLOBBY`).
4. Use `stowaway` (constructor arg on both `ServerAgent`/`server_main()` and `ClientAgent`) to attach
   arbitrary application state to each connection without subclassing the agent classes themselves.

## Known rough edges (don't be surprised by these)

- Hardcoded DB filename `"userdata.db"` is used directly (bypassing `DATABASE_LOCATION`) in several
  `ServerAgent` validation methods (`check_valid_username`, `check_valid_email`, `check_login`) — this is
  pre-existing, not a typo you need to fix incidentally.
  Passwords are hashed with unsalted SHA-256.
- `server_main_loop`'s `sock.accept()` loop unconditionally sets `sa.enforce_password_rules = False`.
- Several commented-out blocks (`sharedata_objects`/`master_mutex` in `pf_server.py`) are dead code from a
  predecessor to the lobby system — left in place intentionally per recent commit history, not cruft to prune
  without checking first.
