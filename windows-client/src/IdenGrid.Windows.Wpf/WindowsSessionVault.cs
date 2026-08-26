using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using IdenGrid.Core;

namespace IdenGrid.Windows.Wpf;

public sealed record StoredDeviceSession(
    string RefreshToken,
    string DeviceSessionId,
    DateTimeOffset RefreshExpiresAt);

public sealed class WindowsSessionVault
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("IdenGrid.Windows.Session.v1");
    private readonly string _path;

    public WindowsSessionVault()
    {
        var root = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "IdenGrid");
        Directory.CreateDirectory(root);
        _path = Path.Combine(root, "device-session.dat");
    }

    public void Save(SessionDto session)
    {
        var stored = new StoredDeviceSession(
            session.RefreshToken,
            session.DeviceSessionId,
            session.RefreshExpiresAt);
        var plain = JsonSerializer.SerializeToUtf8Bytes(stored, JsonDefaults.Options);
        var encrypted = ProtectedData.Protect(plain, Entropy, DataProtectionScope.CurrentUser);
        var temporary = _path + ".tmp";
        File.WriteAllBytes(temporary, encrypted);
        File.Move(temporary, _path, true);
        CryptographicOperations.ZeroMemory(plain);
    }

    public StoredDeviceSession? Load()
    {
        if (!File.Exists(_path)) return null;
        try
        {
            var encrypted = File.ReadAllBytes(_path);
            var plain = ProtectedData.Unprotect(encrypted, Entropy, DataProtectionScope.CurrentUser);
            try
            {
                var stored = JsonSerializer.Deserialize<StoredDeviceSession>(plain, JsonDefaults.Options);
                if (stored is null || stored.RefreshExpiresAt <= DateTimeOffset.UtcNow)
                {
                    Clear();
                    return null;
                }
                return stored;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plain);
            }
        }
        catch (CryptographicException)
        {
            Clear();
            return null;
        }
        catch (JsonException)
        {
            Clear();
            return null;
        }
        catch (IOException)
        {
            Clear();
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }

    public void Clear()
    {
        try { File.Delete(_path); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
