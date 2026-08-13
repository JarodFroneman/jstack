using System;
using TenantDocuments;

static void Require(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}

var service = new TenantDocumentService(
    new[]
    {
        new Document("doc-100", "tenant-a", "quarterly report"),
        new Document("doc-200", "tenant-b", "supplier agreement"),
    }
);

var ownDocument = service.Find("tenant-a", "doc-100");
Require(ownDocument is not null, "same-tenant document should be found");
Require(ownDocument!.Contents == "quarterly report", "document contents changed");
Require(service.Find("tenant-a", "missing") is null, "missing document should return null");
Require(service.Find("", "doc-100") is null, "empty tenant should return null");

Console.WriteLine("4 public assertions passed");
