// Provenance: bigfivefoods/supplieradvisor-mvp PATCH (vuln).
// repo: bigfivefoods/supplieradvisor-mvp
// commit: a7a9bc260d649ea2e582c07435bfd7d93100647b
// parent: a7a9bc260d649ea2e582c07435bfd7d93100647b
// commit_url: https://github.com/bigfivefoods/supplieradvisor-mvp/commit/387bcf40e984a2ee1832ab7beabf0284c5b627d8
// cve: 
// license: MIT
// function: PATCH
// relpath: app/api/customers/claims/route.ts
// provenance: agent
// mechanism: identity_from_request_body
// upstream_start: 90

export async function PATCH(request: NextRequest) {
  try {
    const body = await request.json();
    if (!body.id) return NextResponse.json({ error: 'id required' }, { status: 400 });
    const fields = [
      'status',
      'priority',
      'title',
      'description',
      'amount_claimed',
      'amount_approved',
      'resolution_notes',
      'owner_name',
      'claim_type',
    ] as const;
    const updates: Record<string, unknown> = { updated_at: new Date().toISOString() };
    for (const f of fields) {
      if (body[f] !== undefined) updates[f] = body[f];
    }
    if (['resolved', 'closed', 'approved', 'rejected'].includes(String(body.status))) {
      updates.resolved_at = new Date().toISOString();
    }
    const supabase = getSupabaseServer();
    const { data, error } = await supabase
      .from('customer_claims')
      .update(updates)
      .eq('id', Number(body.id))
      .select('*')
      .single();
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });
    return NextResponse.json({ success: true, claim: data });
  } catch (e: unknown) {
    return NextResponse.json({ error: e instanceof Error ? e.message : 'Error' }, { status: 500 });
  }
}
