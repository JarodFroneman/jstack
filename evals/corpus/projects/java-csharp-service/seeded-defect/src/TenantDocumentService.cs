using System;
using System.Collections.Generic;

namespace TenantDocuments;

public sealed record Document(string Id, string TenantId, string Contents);

public sealed class TenantDocumentService
{
    private readonly IReadOnlyDictionary<string, Document> documents;

    public TenantDocumentService(IEnumerable<Document> source)
    {
        var byId = new Dictionary<string, Document>(StringComparer.Ordinal);
        foreach (var document in source)
        {
            byId.Add(document.Id, document);
        }

        documents = byId;
    }

    public Document? Find(string tenantId, string documentId)
    {
        if (string.IsNullOrWhiteSpace(tenantId) || string.IsNullOrWhiteSpace(documentId))
        {
            return null;
        }

        return documents.TryGetValue(documentId, out var document) ? document : null;
    }
}
