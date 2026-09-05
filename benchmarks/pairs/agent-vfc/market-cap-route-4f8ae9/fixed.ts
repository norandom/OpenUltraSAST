// Provenance: navaneethbv/market-cap  (fixed).
// repo: navaneethbv/market-cap
// commit: 4f8ae9be5519ced5a975f1190e3e4bc43f84e4d6
// parent: fec6f024ce72c9c47b61cbac6ce7a35cb2280602
// commit_url: https://github.com/navaneethbv/market-cap/commit/4f8ae9be5519ced5a975f1190e3e4bc43f84e4d6
// cve: 
// license: MIT
// function: GET
// relpath: app/auth/confirm/route.ts
// provenance: agent
// mechanism: source_reaches_sink

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const token_hash = searchParams.get("token_hash");
  const type = searchParams.get("type") as EmailOtpType | null;
  const nextParam = searchParams.get("next") ?? "/";
  // Only allow same-origin relative paths to prevent open redirects
  const next =
    nextParam.startsWith("/") && !nextParam.startsWith("//") ? nextParam : "/";

  if (token_hash && type) {
    const supabase = await createClient();
    const { error } = await supabase.auth.verifyOtp({ type, token_hash });
    if (!error) {
      return NextResponse.redirect(new URL(next, request.url));
    }
  }

  return NextResponse.redirect(new URL("/login?error=confirm", request.url));
}
