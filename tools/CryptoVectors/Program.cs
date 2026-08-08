// Cross-validates the Python crypto/protocol port against the real Chaos libraries.
//
//   gen-server <out.json>       - emits encrypted server->client packets for Python to decrypt & parse
//   verify-client <in.json>     - decrypts Python's client->server login packets and reports the result
//
// Run via tools/validate_crypto.py, which wires both directions together.

using System.Buffers;
using System.Text;
using Chaos.Cryptography;
using Chaos.DarkAges.Definitions;
using Chaos.Extensions.Common;
using Chaos.IO.Definitions;
using Chaos.IO.Memory;
using Chaos.Networking.Converters.Client;
using Chaos.Networking.Entities;
using Chaos.Networking.Entities.Client;
using Chaos.Networking.Entities.Server;
using Chaos.Packets;
using Chaos.Packets.Abstractions;
using System.Text.Json;

internal static class Program
{
    private static readonly Encoding Enc = Encoding.GetEncoding(949);

    private static int Main(string[] args)
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

        if (args.Length < 2)
        {
            Console.Error.WriteLine("usage: CryptoVectors <gen-server|verify-client> <path>");
            return 1;
        }

        return args[0] switch
        {
            "gen-server"             => GenServer(args[1]),
            "verify-client"          => VerifyClient(args[1]),
            "gen-client-encrypted"   => GenClientEncrypted(args[1]),
            "verify-server-encrypted" => VerifyServerEncrypted(args[1]),
            _                        => Fail($"unknown command {args[0]}")
        };
    }

    // seeds/keys/sequences shared by the server-crypto round-trip checks
    private static readonly (byte seed, string key, string keySalt, byte sequence)[] Setups =
    [
        (0, "UrkcnItnI", "default", 0),
        (3, "ABCDEFGHI", "default", 7),
        (9, "keythatis9", "Shanadal", 200),
        (5, "mixedKeys1", "somechar", 42)
    ];

    // opcodes exercised: 0x03 NORMAL (login), 0x18 MD5 (world list request); both non-dialog
    private static readonly byte[] ClientOpCodes = [0x03, 0x18];

    private static int GenClientEncrypted(string path)
    {
        // Chaos ClientEncrypt -> Python server_decrypt must recover the plaintext
        var vectors = new List<object>();

        foreach (var (seed, key, keySalt, sequence) in Setups)
        {
            var crypto = new Crypto(seed, key, keySalt);

            foreach (var opCode in ClientOpCodes)
            {
                var plaintext = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03 };
                Span<byte> buffer = plaintext.AsSpan();
                crypto.ClientEncrypt(ref buffer, opCode, sequence);

                vectors.Add(new
                {
                    seed,
                    key,
                    keySalt,
                    sequence,
                    opCode,
                    plaintextHex = Hex(plaintext),
                    encryptedHex = Hex(buffer)
                });
            }
        }

        File.WriteAllText(path, JsonSerializer.Serialize(vectors, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"wrote {vectors.Count} client-encrypted vectors to {path}");
        return 0;
    }

    private static int VerifyServerEncrypted(string path)
    {
        // Python server_encrypt -> Chaos ClientDecrypt must recover the plaintext
        var inputs = JsonSerializer.Deserialize<List<ServerEncVector>>(File.ReadAllText(path))!;
        var results = new List<object>();
        var allOk = true;

        foreach (var vector in inputs)
        {
            var crypto = new Crypto((byte)vector.Seed, vector.Key, vector.KeySalt);
            Span<byte> buffer = Convert.FromHexString(vector.EncryptedHex).AsSpan();
            crypto.ClientDecrypt(ref buffer, (byte)vector.OpCode, (byte)vector.Sequence);

            var recovered = Hex(buffer);
            var ok = recovered == vector.PlaintextHex.ToUpperInvariant();
            allOk &= ok;
            results.Add(new { ok, expected = vector.PlaintextHex, recovered });
        }

        File.WriteAllText(
            Path.ChangeExtension(path, ".result.json"),
            JsonSerializer.Serialize(results, new JsonSerializerOptions { WriteIndented = true }));

        Console.WriteLine($"verified {inputs.Count} server-encrypted vectors; all ok = {allOk}");
        return allOk ? 0 : 2;
    }

    private sealed record ServerEncVector(int Seed, string Key, string KeySalt, int Sequence, int OpCode, string EncryptedHex, string PlaintextHex);

    private static int Fail(string message)
    {
        Console.Error.WriteLine(message);
        return 1;
    }

    private static PacketSerializer BuildSerializer()
    {
        var converters = new Dictionary<Type, IPacketConverter>();

        foreach (var type in typeof(IPacketConverter<>).LoadImplementations())
        {
            var instance = (IPacketConverter)Activator.CreateInstance(type)!;
            var argType = instance.GetType()
                                  .GetInterfaces()
                                  .Where(i => i.IsGenericType)
                                  .First(i => i.GetGenericTypeDefinition() == typeof(IPacketConverter<>))
                                  .GetGenericArguments()[0];
            converters.TryAdd(argType, instance);
        }

        return new PacketSerializer(Enc, converters);
    }

    private static string Hex(ReadOnlySpan<byte> bytes) => Convert.ToHexString(bytes);

    private static byte[] Encrypt(Crypto crypto, PacketSerializer serializer, IPacketSerializable args, byte sequence, out byte opCode, out byte[] plaintext)
    {
        var packet = serializer.Serialize(args);
        opCode = packet.OpCode;
        plaintext = packet.Buffer.ToArray();

        var owner = packet.MemoryOwner!;
        var length = packet.Length;
        crypto.ServerEncrypt(ref owner, ref length, opCode, sequence);

        return owner.Memory.Span[..length].ToArray();
    }

    private static int GenServer(string path)
    {
        var serializer = BuildSerializer();
        var vectors = new List<object>();

        // a spread of seeds, sequences, and both encryption modes
        (byte seed, string key, string keySalt, byte sequence)[] setups =
        [
            (0, "UrkcnItnI", "default", 0),
            (3, "ABCDEFGHI", "default", 7),
            (9, "keythatis9", "Shanadal", 200),
            (5, "mixedKeys1", "somechar", 42)
        ];

        foreach (var (seed, key, keySalt, sequence) in setups)
        {
            var crypto = new Crypto(seed, key, keySalt);

            // WorldList (MD5 mode, opcode 0x36) with a realistic country list
            var worldList = new WorldListArgs
            {
                WorldMemberCount = 3,
                CountryList =
                [
                    new WorldListMemberInfo { BaseClass = BaseClass.Monk, Color = WorldListColor.White, SocialStatus = SocialStatus.Awake, Title = "Grandmaster", IsMaster = true, IsGuilded = true, Name = "Alice" },
                    new WorldListMemberInfo { BaseClass = BaseClass.Wizard, Color = WorldListColor.Orange, SocialStatus = SocialStatus.DayDreaming, Title = "", IsMaster = false, IsGuilded = false, Name = "Bob" },
                    new WorldListMemberInfo { BaseClass = BaseClass.Warrior, Color = WorldListColor.Red, SocialStatus = SocialStatus.NeedGroup, Title = "Knight", IsMaster = false, IsGuilded = false, Name = "Carol" }
                ]
            };

            var encrypted = Encrypt(crypto, serializer, worldList, sequence, out var opCode, out var plaintext);

            vectors.Add(new
            {
                kind = "worldlist",
                seed,
                key,
                keySalt,
                sequence,
                opCode,
                plaintextHex = Hex(plaintext),
                encryptedHex = Hex(encrypted),
                memberCount = worldList.WorldMemberCount,
                members = worldList.CountryList.Select(m => new
                {
                    baseClass = (int)m.BaseClass,
                    isGuilded = m.IsGuilded,
                    name = m.Name
                }).ToArray()
            });

            // LoginMessage (NORMAL mode, opcode 0x02)
            var loginMessage = new LoginMessageArgs { LoginMessageType = LoginMessageType.Confirm, Message = "welcome" };
            var loginEncrypted = Encrypt(crypto, serializer, loginMessage, sequence, out var loginOp, out var loginPlain);

            vectors.Add(new
            {
                kind = "raw",
                seed,
                key,
                keySalt,
                sequence,
                opCode = loginOp,
                plaintextHex = Hex(loginPlain),
                encryptedHex = Hex(loginEncrypted)
            });
        }

        File.WriteAllText(path, JsonSerializer.Serialize(vectors, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"wrote {vectors.Count} server vectors to {path}");
        return 0;
    }

    private static int VerifyClient(string path)
    {
        var inputs = JsonSerializer.Deserialize<List<ClientVector>>(File.ReadAllText(path))!;
        var results = new List<object>();
        var allOk = true;

        foreach (var vector in inputs)
        {
            var crypto = new Crypto((byte)vector.Seed, vector.Key, vector.KeySalt);
            var buffer = Convert.FromHexString(vector.EncryptedHex).AsSpan();

            crypto.ServerDecrypt(ref buffer, (byte)vector.OpCode, (byte)vector.Sequence);

            var reader = new SpanReader(Enc, in buffer, Endianness.BigEndian);
            var login = new LoginConverter().Deserialize(ref reader);

            var ok = login.Name == vector.ExpectedName
                     && login.Password == vector.ExpectedPassword
                     && login.IsValid;
            allOk &= ok;

            results.Add(new
            {
                ok,
                name = login.Name,
                password = login.Password,
                isValid = login.IsValid,
                expectedName = vector.ExpectedName,
                expectedPassword = vector.ExpectedPassword
            });
        }

        File.WriteAllText(
            Path.ChangeExtension(path, ".result.json"),
            JsonSerializer.Serialize(results, new JsonSerializerOptions { WriteIndented = true }));

        Console.WriteLine($"verified {inputs.Count} client vectors; all valid = {allOk}");
        return allOk ? 0 : 2;
    }

    private sealed record ClientVector(
        int Seed,
        string Key,
        string KeySalt,
        int Sequence,
        int OpCode,
        string EncryptedHex,
        string ExpectedName,
        string ExpectedPassword);
}
