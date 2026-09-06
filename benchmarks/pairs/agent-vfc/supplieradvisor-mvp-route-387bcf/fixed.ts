// Provenance: bigfivefoods/supplieradvisor-mvp PATCH (fixed).
// repo: bigfivefoods/supplieradvisor-mvp
// commit: 387bcf40e984a2ee1832ab7beabf0284c5b627d8
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
    const claimId = Number(body.id);
    const companyId = Number(body.companyId);
    if (!Number.isFinite(claimId) || claimId <= 0) {
      return NextResponse.json({ error: 'id required' }, { status: 400 });
    }
    if (!Number.isFinite(companyId) || companyId <= 0) {
      return NextResponse.json({ error: 'companyId required' }, { status: 400 });
    }

    const _gate = await requireCompanyAccess(request, companyId, { legacyPrivyUserId: legacyPrivyFrom(request) });
    if (!_gate.ok) return _gate.response;

    const supabase = getSupabaseServer();
    const { data: existing, error: fetchError } = await supabase
      .from('customer_claims')
      .select('*')
      .eq('id', claimId)
      .eq('profile_id', companyId)
      .single();
    if (fetchError || !existing) {
      return NextResponse.json({ error: 'Claim not found' }, { status: 404 });
    }

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
    const { data, error } = await supabase
      .from('customer_claims')
      .update(updates)
      .eq('id', claimId)
      .eq('profile_id', companyId)
      .select('*')
      .single();
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });
    return NextResponse.json({ success: true, claim: data });
  } catch (e: unknown) {
    return NextResponse.json({ error: e instanceof Error ? e.message : 'Error' }, { status: 500 });
  }
}
