using System;
using System.Buffers;
using System.Diagnostics.Contracts;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

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
        // Skip UTF-8 BOM if present
        if (utf8.Length >= 3 && utf8[0] == 0xEF && utf8[1] == 0xBB && utf8[2] == 0xBF)
            utf8 = utf8[3..];

        // Skip leading whitespace
        int i = 0;
        while (i < utf8.Length)
        {
            byte c = utf8[i];
            if (c is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n') { i++; continue; }
            // Allow either object or array as first token
            return c == (byte)'{' || c == (byte)'[';
        }
        return false;
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