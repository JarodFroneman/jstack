using System;
using System.Text.Json;

namespace ProfileUpdates;

public sealed record Profile(string DisplayName, bool IsAdmin);

public sealed class ProfileUpdateService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
    };

    public Profile Update(string json, bool authenticatedIsAdmin)
    {
        var update = JsonSerializer.Deserialize<UpdateRequest>(json, JsonOptions)
            ?? throw new ArgumentException("profile update body is required", nameof(json));
        var displayName = update.DisplayName?.Trim() ?? string.Empty;
        if (displayName.Length == 0 || displayName.Length > 80)
        {
            throw new ArgumentException("displayName must contain 1 to 80 characters", nameof(json));
        }

        return new Profile(displayName, authenticatedIsAdmin);
    }

    private sealed class UpdateRequest
    {
        public UpdateRequest()
        {
        }

        public string? DisplayName { get; set; }
    }
}
