"""End-to-end crypto validation against the real Chaos libraries.

Runs both directions:

  1. The C# harness encrypts server->client packets; Python decrypts and parses them.
  2. Python encrypts client->server login packets; the C# harness decrypts and
     confirms the server would accept them (name/password intact, CRCs valid).

Requires the CryptoVectors harness to be built (dotnet build -c Release).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from population_tracker import protocol as p  # noqa: E402
from population_tracker.crypto import Crypto  # noqa: E402

HARNESS_DIR = ROOT / "tools" / "CryptoVectors"
HARNESS_DLL = HARNESS_DIR / "bin" / "Release" / "net10.0" / "CryptoVectors.dll"
WORK = ROOT / "tools" / "_vectors"


def run_harness(*args: str) -> None:
    subprocess.run(["dotnet", str(HARNESS_DLL), *args], check=True, cwd=HARNESS_DIR)


def verify_server_vectors() -> int:
    """C# encrypted -> Python decrypts and parses."""
    path = WORK / "server_vectors.json"
    run_harness("gen-server", str(path))
    vectors = json.loads(path.read_text())
    failures = 0

    for vector in vectors:
        crypto = Crypto(vector["seed"], vector["key"], vector["keySalt"])
        encrypted = bytes.fromhex(vector["encryptedHex"])
        expected = bytes.fromhex(vector["plaintextHex"])
        decrypted = crypto.client_decrypt(encrypted, vector["opCode"], vector["sequence"])

        if decrypted != expected:
            failures += 1
            print(f"  DECRYPT MISMATCH op=0x{vector['opCode']:02X} seed={vector['seed']}")
            print(f"    expected {expected.hex()}")
            print(f"    got      {decrypted.hex()}")
            continue

        if vector["kind"] == "worldlist":
            world_list = p.parse_world_list(decrypted)

            if world_list.member_count != vector["memberCount"]:
                failures += 1
                print(f"  COUNT MISMATCH {world_list.member_count} != {vector['memberCount']}")

            for parsed, ref in zip(world_list.members, vector["members"], strict=True):
                if parsed.base_class != ref["baseClass"] or parsed.name != ref["name"] or parsed.is_guilded != ref["isGuilded"]:
                    failures += 1
                    print(f"  MEMBER MISMATCH {parsed} != {ref}")

    print(f"server->client: {len(vectors) - failures}/{len(vectors)} vectors passed")
    return failures


def verify_client_vectors() -> int:
    """Python encrypts login -> C# decrypts and validates."""
    # include non-1/1 client ids to prove the integrity block validates for
    # the random ids the client now generates each run
    setups = [
        (0, "UrkcnItnI", "", 0, "Alice", "hunter2", 1, 1),
        (3, "ABCDEFGHI", "", 1, "Bob", "p@ssw0rd", 2**31 - 2, 12345),
        (9, "keythatis9", "", 5, "Carol", "longerpasswordhere", 987654321, 2**31 - 2),
        (5, "mixedKeys1", "", 200, "Dave", "x", 42, 2000000000),
    ]
    vectors = []

    for seed, key, key_salt, sequence, name, password, client_id1, client_id2 in setups:
        crypto = Crypto(seed, key, key_salt)
        body = p.login_body(name, password, client_id1=client_id1, client_id2=client_id2)
        encrypted = crypto.client_encrypt(body, p.ClientOpCode.LOGIN, sequence)
        vectors.append(
            {
                "Seed": seed,
                "Key": key,
                "KeySalt": key_salt,
                "Sequence": sequence,
                "OpCode": int(p.ClientOpCode.LOGIN),
                "EncryptedHex": encrypted.hex().upper(),
                "ExpectedName": name,
                "ExpectedPassword": password,
            }
        )

    path = WORK / "client_vectors.json"
    path.write_text(json.dumps(vectors, indent=2))

    result = subprocess.run(
        ["dotnet", str(HARNESS_DLL), "verify-client", str(path)],
        cwd=HARNESS_DIR,
    )

    results = json.loads((WORK / "client_vectors.result.json").read_text())
    failures = sum(1 for r in results if not r["ok"])

    for r in results:
        if not r["ok"]:
            print(f"  LOGIN REJECTED name={r['name']!r} isValid={r['isValid']}")

    print(f"client->server: {len(results) - failures}/{len(results)} logins accepted")
    return failures + (result.returncode if result.returncode == 1 else 0)


def verify_server_decrypt() -> int:
    """C# ClientEncrypt -> Python server_decrypt recovers the plaintext."""
    path = WORK / "client_encrypted.json"
    run_harness("gen-client-encrypted", str(path))
    vectors = json.loads(path.read_text())
    failures = 0

    for vector in vectors:
        crypto = Crypto(vector["seed"], vector["key"], vector["keySalt"])
        encrypted = bytes.fromhex(vector["encryptedHex"])
        expected = bytes.fromhex(vector["plaintextHex"])
        recovered = crypto.server_decrypt(encrypted, vector["opCode"], vector["sequence"])

        if recovered != expected:
            failures += 1
            print(f"  SERVER_DECRYPT MISMATCH op=0x{vector['opCode']:02X} seed={vector['seed']}")

    print(f"server_decrypt: {len(vectors) - failures}/{len(vectors)} vectors passed")
    return failures


def verify_server_encrypt() -> int:
    """Python server_encrypt -> C# ClientDecrypt recovers the plaintext."""
    setups = [
        (0, "UrkcnItnI", "default", 0),
        (3, "ABCDEFGHI", "default", 7),
        (9, "keythatis9", "Shanadal", 200),
        (5, "mixedKeys1", "somechar", 42),
    ]
    # 0x36 WorldList (MD5), 0x02 LoginMessage (NORMAL)
    opcodes = [0x36, 0x02]
    vectors = []

    for seed, key, key_salt, sequence in setups:
        crypto = Crypto(seed, key, key_salt)

        for opcode in opcodes:
            plaintext = bytes([0x01, 0x02, 0x03, 0x04, 0xAA, 0xBB])
            encrypted = crypto.server_encrypt(plaintext, opcode, sequence)
            vectors.append(
                {
                    "Seed": seed,
                    "Key": key,
                    "KeySalt": key_salt,
                    "Sequence": sequence,
                    "OpCode": opcode,
                    "EncryptedHex": encrypted.hex().upper(),
                    "PlaintextHex": plaintext.hex().upper(),
                }
            )

    path = WORK / "server_encrypted.json"
    path.write_text(json.dumps(vectors, indent=2))
    result = subprocess.run(["dotnet", str(HARNESS_DLL), "verify-server-encrypted", str(path)], cwd=HARNESS_DIR)
    results = json.loads((WORK / "server_encrypted.result.json").read_text())
    failures = sum(1 for r in results if not r["ok"])

    print(f"server_encrypt: {len(results) - failures}/{len(results)} vectors passed")
    return failures + (1 if result.returncode == 1 else 0)


def main() -> int:
    if not HARNESS_DLL.is_file():
        print(f"harness not built; run: dotnet build -c Release {HARNESS_DIR}", file=sys.stderr)
        return 1

    WORK.mkdir(exist_ok=True)
    failures = (
        verify_server_vectors()
        + verify_client_vectors()
        + verify_server_decrypt()
        + verify_server_encrypt()
    )

    if failures:
        print(f"\nFAILED: {failures} mismatch(es)")
        return 1

    print("\nOK: Python crypto matches the Chaos libraries in both directions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
