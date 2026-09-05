// Provenance: handielson/Mercado-do-vale-news  (vuln).
// repo: handielson/Mercado-do-vale-news
// commit: 70ca282b819ac1d60f4b5e665d224b1043ff1ccc
// parent: 70ca282b819ac1d60f4b5e665d224b1043ff1ccc
// commit_url: https://github.com/handielson/Mercado-do-vale-news/commit/9b5fcf2dae41e56f5f97952266f2d6ba59598598
// cve: 
// license: MIT
// function: fetchMetadata
// relpath: services/catalogMetadataService.ts
// provenance: agent
// mechanism: permissive_default

async function fetchMetadata(): Promise<MetadataCache | null> {
    // Deduplicação de requisições concorrentes
    if (pendingFetch) return pendingFetch;

    pendingFetch = (async () => {
        try {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), 10000);
            
            // Bypass completo de cache de CDN e Browser
            const timestamp = Date.now();
            const res = await fetch(buildVpsUrl(`/catalog/metadata?_t=${timestamp}`), {
                signal: controller.signal,
                headers: { 
                    Accept: 'application/json',
                    'Cache-Control': 'no-cache, no-store, must-revalidate',
                    'Pragma': 'no-cache'
                },
                cache: 'no-store',
            });
            clearTimeout(timer);
            if (!res.ok) return null;
            const data = await res.json();
            return {
                categories: data.categories || [],
                brands: data.brands || [],
                priceRange: data.priceRange || null,
                timestamp: Date.now(),
            };
        } catch {
            return null;
        } finally {
            pendingFetch = null;
        }
    })();

    return pendingFetch;
}
