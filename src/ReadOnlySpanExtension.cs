using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace Soenneker.Extensions.Spans.Readonly;

/// <summary>
/// A collection of helpful ReadOnlySpan extension methods
/// </summary>
public static class ReadOnlySpanExtension
{
    /// <summary>
    /// Bytes -> SHA256 hex (uppercase by default)
    /// </summary>
    /// <param name="data"></param>
    /// <param name="upperCase"></param>
    /// <returns></returns>
    public static string ToSha256Hex(this ReadOnlySpan<byte> data, bool upperCase = true)
    {
        Span<byte> hash = stackalloc byte[32]; // SHA-256
        SHA256.TryHashData(data, hash, out _); // avoids SHA256.Create()

        string hex = Convert.ToHexString(hash); // A-F uppercase by default
        return upperCase ? hex : hex.ToLowerInvariant();
    }

    /// <summary>
    /// Text -> SHA256 hex (UTF-8 by default)
    /// </summary>
    /// <param name="text"></param>
    /// <param name="encoding"></param>
    /// <param name="upperCase"></param>
    /// <returns></returns>
    public static string ToSha256Hex(this ReadOnlySpan<char> text, Encoding? encoding = null, bool upperCase = true)
    {
        encoding ??= Encoding.UTF8;

        int byteCount = encoding.GetByteCount(text);
        if (byteCount <= 1024) // stackalloc fast-path
        {
            Span<byte> tmp = stackalloc byte[byteCount];
            encoding.GetBytes(text, tmp);

            ReadOnlySpan<byte> ro = tmp; // implicit conversion
            return ro.ToSha256Hex(upperCase);
        }

        byte[] rented = ArrayPool<byte>.Shared.Rent(byteCount);
        try
        {
            int written = encoding.GetBytes(text, rented);
            return ((ReadOnlySpan<byte>) rented.AsSpan(0, written)).ToSha256Hex(upperCase);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }
}