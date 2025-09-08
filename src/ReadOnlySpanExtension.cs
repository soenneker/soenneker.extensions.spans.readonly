using System;
using System.Buffers;
using System.Diagnostics.Contracts;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Soenneker.Enums.ContentKinds;

namespace Soenneker.Extensions.Spans.Readonly;

public static class ReadOnlySpanExtension
{
    private static readonly SearchValues<byte> _ws = SearchValues.Create(" \t\r\n"u8);

    /// <summary>Bytes → SHA-256 hex (uppercase by default)</summary>
    [Pure, MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public static string ToSha256Hex(this ReadOnlySpan<byte> data, bool upperCase = true)
    {
        Span<byte> hash = stackalloc byte[32]; // SHA-256 output (uninitialized is fine)
        SHA256.TryHashData(data, hash, out _);
        return upperCase ? Convert.ToHexString(hash) : Convert.ToHexStringLower(hash);
    }

    [Pure, MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool LooksLikeJson(this ReadOnlySpan<byte> utf8) => Classify(utf8) == ContentKind.Json;

    [Pure, MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool LooksLikeXmlOrHtml(this ReadOnlySpan<byte> utf8) => Classify(utf8) == ContentKind.XmlOrHtml;

    [Pure, MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool LooksBinary(this ReadOnlySpan<byte> utf8) => Classify(utf8) == ContentKind.Binary;

    [Pure, MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static ContentKind Classify(this ReadOnlySpan<byte> utf8)
    {
        // Skip UTF-8 BOM
        if (utf8.Length >= 3 && utf8[0] == 0xEF && utf8[1] == 0xBB && utf8[2] == 0xBF)
            utf8 = utf8[3..];

        if (utf8.IsEmpty)
            return ContentKind.Unknown;

        // Quick binary heuristic (first 512 bytes)
        int limit = utf8.Length < 512 ? utf8.Length : 512;
        ReadOnlySpan<byte> head = utf8.Slice(0, limit);

        // NUL is a strong binary signal; this is fast (vectorized internally)
        if (head.IndexOf((byte)0) >= 0)
            return ContentKind.Binary;

        // Count C0 controls except \t \n \r
        var controls = 0;

        for (var i = 0; i < head.Length; i++)
        {
            byte b = head[i];
            if (b < 0x20 && b != (byte)'\t' && b != (byte)'\n' && b != (byte)'\r')
                controls++;
        }

        if (controls > limit / 10) // >10% controls => likely binary
            return ContentKind.Binary;

        // Skip RFC 8259 JSON whitespace in one shot
        int idx = utf8.IndexOfAnyExcept(_ws);
        if (idx < 0)
            return ContentKind.Unknown;

        byte c = utf8[idx];

        switch (c)
        {
            // JSON containers
            case (byte)'{' or (byte)'[':
            // JSON top-level primitives
            case (byte)'"':
            case (byte)'-':
            case >= (byte)'0' and <= (byte)'9':
            // true/false/null
            case (byte)'t' or (byte)'f' or (byte)'n':
                return ContentKind.Json;
            case (byte)'<':
                return ContentKind.XmlOrHtml;
            default:
                return ContentKind.Text;
        }
    }

    /// <summary>Text → SHA-256 hex (UTF-8 by default)</summary>
    [Pure, MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static string ToSha256Hex(this ReadOnlySpan<char> text, Encoding? encoding = null, bool upperCase = true)
    {
        encoding ??= Encoding.UTF8;
        int byteCount = encoding.GetByteCount(text);

        // Stack fast-path
        if (byteCount <= 1024)
        {
            Span<byte> tmp = stackalloc byte[byteCount];
            encoding.GetBytes(text, tmp);
            return ((ReadOnlySpan<byte>)tmp).ToSha256Hex(upperCase);
        }

        // Pool fallback for moderately large inputs
        if (byteCount <= 128 * 1024)
        {
            byte[] rented = ArrayPool<byte>.Shared.Rent(byteCount);
            try
            {
                int written = encoding.GetBytes(text, rented);
                return new ReadOnlySpan<byte>(rented, 0, written).ToSha256Hex(upperCase);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }

        // Very large inputs: stream to avoid big rents
        return ToSha256HexStreaming(text, encoding, upperCase);
    }

    // Streaming path for huge inputs (avoids renting a giant buffer)
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static string ToSha256HexStreaming(ReadOnlySpan<char> text, Encoding encoding, bool upperCase)
    {
        using var ih = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Encoder encoder = encoding.GetEncoder();

        const int charChunk = 4096;
        int maxBytesPerChar = Math.Max(1, encoding.GetMaxByteCount(1)); // conservative bound
        byte[] buffer = ArrayPool<byte>.Shared.Rent(charChunk * maxBytesPerChar);

        try
        {
            for (var i = 0; i < text.Length; i += charChunk)
            {
                ReadOnlySpan<char> slice = text.Slice(i, Math.Min(charChunk, text.Length - i));
                encoder.Convert(slice, buffer, flush: i + slice.Length >= text.Length, out int charsUsed, out int bytesUsed, out _);
                ih.AppendData(buffer, 0, bytesUsed);
            }

            Span<byte> hash = stackalloc byte[32];
            ih.TryGetHashAndReset(hash, out _);
            return upperCase ? Convert.ToHexString(hash) : Convert.ToHexStringLower(hash);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}