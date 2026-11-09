using System.Collections.Concurrent;
using Microsoft.AspNetCore.Identity;

namespace AuthApi;

#region user
public sealed record User(
    Guid Id, string Email, string PasswordHash, string Role);
#endregion

// In memory, so the example runs without a database.
internal sealed class UserStore(AuthAppOptions opts)
{
    readonly ConcurrentDictionary<string, User> _byEmail =
        new(StringComparer.OrdinalIgnoreCase);
    readonly PasswordHasher<User> _hasher = new();
    static readonly User Nobody = new(Guid.Empty, "", "", "");
    readonly Lazy<string> _dummyHash = new(() =>
        new PasswordHasher<User>().HashPassword(Nobody, "dummy"));

    #region register
    public User? Register(string email, string password, string role)
    {
        var user = new User(Guid.NewGuid(), email, "", role);
        // the hash, never the password, is what gets stored
        user = user with
        {
            PasswordHash = _hasher.HashPassword(user, password)
        };
        return _byEmail.TryAdd(email, user) ? user : null;
    }
    #endregion

    #region check
    public User? CheckPassword(string email, string password)
    {
        if (!_byEmail.TryGetValue(email, out var user))
        {
            // pay the same ~40 ms of a real check, so the
            // response time does not tell which emails exist
            if (!opts.SkipDummyHash)
                _hasher.VerifyHashedPassword(
                    Nobody, _dummyHash.Value, password);
            return null;
        }
        var result = _hasher.VerifyHashedPassword(
            user, user.PasswordHash, password);
        return result == PasswordVerificationResult.Failed
            ? null : user;
    }
    #endregion

    public User? Find(Guid id) =>
        _byEmail.Values.FirstOrDefault(u => u.Id == id);

    public User? FindByEmail(string email) =>
        _byEmail.GetValueOrDefault(email);
}
