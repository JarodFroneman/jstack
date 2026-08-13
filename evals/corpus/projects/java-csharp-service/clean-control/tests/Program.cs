using System;
using ProfileUpdates;

static void Require(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}

var service = new ProfileUpdateService();

var ordinary = service.Update("{\"displayName\":\"  Ada  \"}", false);
Require(ordinary.DisplayName == "Ada", "displayName should be normalized");
Require(!ordinary.IsAdmin, "ordinary update changed privilege");

var attemptedElevation = service.Update(
    "{\"displayName\":\"Ada\",\"isAdmin\":true}",
    false
);
Require(!attemptedElevation.IsAdmin, "request body must not grant privilege");

var existingAdministrator = service.Update("{\"displayName\":\"Grace\"}", true);
Require(existingAdministrator.IsAdmin, "authenticated privilege should be preserved");

Console.WriteLine("4 public assertions passed");
