// Provenance: Irnhakim/nimestream  (fixed).
// repo: Irnhakim/nimestream
// commit: d17f535bf3012041b056ff3aa991ff6cfa198e43
// parent: 0c37bfd9e5292b15b1d7af51f52793d9bdf1cef0
// commit_url: https://github.com/Irnhakim/nimestream/commit/d17f535bf3012041b056ff3aa991ff6cfa198e43
// cve: 
// license: MIT
// function: GET
// relpath: app/api/img/route.js
// provenance: agent
// mechanism: source_reaches_sink

export async function GET(request) {
  const { searchParams } = new URL(request.url);
  const imageUrl = searchParams.get('url');

  if (!imageUrl) {
    return new Response('Missing url parameter', { status: 400 });
  }

  // Only allow proxying images from allowed domains for security
  const allowed = [
    'otakudesu.blog', 'otakudesu.cloud', 'otakudesu.ltd',
    'i3.wp.com', 'i2.wp.com', 'i1.wp.com', 'i0.wp.com',
    'cdn.otakudesu', 'kusonime.com', 'wp-content',
    'oploverz.ac', 'oploverz.site', 'backapi.oploverz', 'alqanime.net',
    'anichin.cafe', 'samehadaku', 'animasu', 'zoronime', 'anoboy', 'nimegami', 'animeindo', 'animekuindo', 'winbu', 'kuramanime', 'animekompi', 'donghub', 'dramabox'
  ];

  let parsedUrl;
  try {
    parsedUrl = new URL(imageUrl);
  } catch (e) {
    return new Response('Invalid URL', { status: 400 });
  }

  const hostname = parsedUrl.hostname;
  const isAllowed = allowed.some(domain =>
    hostname === domain || hostname.endsWith(`.${domain}`)
  );
  if (!isAllowed) {
    return new Response('Forbidden', { status: 403 });
  }

  // Determine proper referer
  let referer = `${BASE_URL}/`;
  if (imageUrl.includes('kusonime.com')) {
    referer = 'https://kusonime.com/';
  } else if (imageUrl.includes('oploverz.ac') || imageUrl.includes('oploverz.site')) {
    referer = 'https://oploverz.site/';
  } else if (imageUrl.includes('alqanime.net')) {
    referer = 'https://alqanime.net/';
  } else if (imageUrl.includes('anichin.cafe')) {
    referer = 'https://anichin.cafe/';
  } else if (imageUrl.includes('samehadaku')) {
    referer = 'https://samehadaku.vip/';
  } else if (imageUrl.includes('animasu')) {
    referer = 'https://animasu.cc/';
  } else if (imageUrl.includes('kuramanime')) {
    referer = 'https://kuramanime.net/';
  }

  try {
    // Add abort controller to prevent long timeout waits
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4000); // 4 seconds timeout limit

    const response = await fetch(imageUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Referer': referer,
        'Accept': 'image/avif,image/webp,image/apng,image/*,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
      },
      signal: controller.signal,
      cache: 'no-store',
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      return new Response('Failed to fetch source image', { status: response.status });
    }

    const contentType = response.headers.get('content-type') || 'image/jpeg';
    const imageBuffer = await response.arrayBuffer();

    return new Response(imageBuffer, {
      status: 200,
      headers: {
        'Content-Type': contentType,
        'Cache-Control': 'public, max-age=86400, stale-while-revalidate=43200',
        'Access-Control-Allow-Origin': '*',
      },
    });
  } catch (err) {
    console.error('Image proxy error:', err.message);
    return new Response('Error loading image', { status: 500 });
  }
}
