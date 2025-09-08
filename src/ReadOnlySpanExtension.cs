using System;
using System.Buffers;
using System.Diagnostics.Contracts;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Soenneker.Enums.ContentKinds;

namespace Soenneker.Extensions.Spans.Readonly;

/// <summary>
/// A collection of helpful ReadOnlySpan extension methods
/// </summary>
public static class ReadOnlySpanExtension
{
    /// <summary>Bytes → SHA-256 hex (uppercase by default)</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    [Pure]
    public static string ToSha256Hex(this ReadOnlySpan<byte> data, bool upperCase = true)
    {
        Span<byte> hash = stackalloc byte[32]; // SHA-256 output
        SHA256.TryHashData(data, hash, out _); // no SHA256.Create()

        return upperCase
            ? Convert.ToHexString(hash) // single allocation (uppercase)
            : Convert.ToHexStringLower(hash); // single allocation (lowercase)
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool LooksLikeJson(this ReadOnlySpan<byte> utf8)
    {
        return Classify(utf8) == ContentKind.Json;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool LooksLikeXmlOrHtml(this ReadOnlySpan<byte> utf8)
    {
        return Classify(utf8) == ContentKind.XmlOrHtml;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool LooksBinaryContent(this ReadOnlySpan<byte> utf8)
    {
        var k = Classify(utf8);
        return k == ContentKind.Binary;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ContentKind Classify(this ReadOnlySpan<byte> utf8)
    {
        // Skip UTF-8 BOM
        if (utf8.Length >= 3 && utf8[0] == 0xEF && utf8[1] == 0xBB && utf8[2] == 0xBF)
            utf8 = utf8[3..];

        if (utf8.IsEmpty)
            return ContentKind.Unknown;

        // Quick binary heuristic on a short head (controls or NULs)
        int limit = Math.Min(utf8.Length, 512);
        var controls = 0;

        for (var i = 0; i < limit; i++)
        {
            byte b = utf8[i];
            if (b == 0) 
                return ContentKind.Binary; // NUL -> binary

            // Count C0 controls except \t \n \r
            if (b < 0x20 && b != (byte)'\t' && b != (byte)'\n' && b != (byte)'\r')
                controls++;
        }

        if (controls > limit / 10) // >10% controls -> probably binary
            return ContentKind.Binary;

        // Skip leading whitespace
        var j = 0;
        while (j < utf8.Length)
        {
            byte c = utf8[j];
            if (c is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n')
            {
                j++;
                continue;
            }

            if (c == (byte)'{' || c == (byte)'[') 
                return ContentKind.Json;

            if (c == (byte)'<') 
                return ContentKind.XmlOrHtml; // includes XML and HTML

            return ContentKind.Text;
        }

        return ContentKind.Unknown;
    }

    /// <summary>Text → SHA-256 hex (UTF-8 by default)</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    [Pure]
    public static string ToSha256Hex(this ReadOnlySpan<char> text, Encoding? encoding = null, bool upperCase = true)
    {
        encoding ??= Encoding.UTF8;

        int byteCount = encoding.GetByteCount(text);

        // Stack fast-path
        if (byteCount <= 1024)
        {
            Span<byte> tmp = stackalloc byte[byteCount];
            encoding.GetBytes(text, tmp);

            ReadOnlySpan<byte> implicitReadOnly = tmp;

            return implicitReadOnly.ToSha256Hex(upperCase);
        }

        // Pool fallback for large inputs
        byte[] rented = ArrayPool<byte>.Shared.Rent(byteCount);
        try
        {
            int written = encoding.GetBytes(text, rented);

            Span<byte> span = rented.AsSpan(0, written);

            ReadOnlySpan<byte> implicitReadOnly = span;

            return implicitReadOnly.ToSha256Hex(upperCase);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }
}