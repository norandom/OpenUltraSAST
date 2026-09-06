// Provenance: bigfivefoods/supplieradvisor-mvp GET (vuln).
// repo: bigfivefoods/supplieradvisor-mvp
// commit: 8558538471e4fb10856f8d9a17d2be5ab5c4fb9c
// parent: 8558538471e4fb10856f8d9a17d2be5ab5c4fb9c
// commit_url: https://github.com/bigfivefoods/supplieradvisor-mvp/commit/a69e8f27c0f4d402573d16f0612b51155bbc46e1
// cve: 
// license: MIT
// function: GET
// relpath: app/api/customers/opportunities/route.ts
// provenance: agent
// mechanism: identity_from_request_body
// upstream_start: 89

export async function GET(request: NextRequest) {
  try {
    const companyId = Number(request.nextUrl.searchParams.get('companyId'));
    const stage = request.nextUrl.searchParams.get('stage');
    const q = (request.nextUrl.searchParams.get('q') || '').trim().toLowerCase();
    if (!Number.isFinite(companyId)) {
      return NextResponse.json({ error: 'companyId required' }, { status: 400 });
    }
    const supabase = getSupabaseServer();
    const { loadHoldingSubtree, annotateGroupOpportunity } = await import(
      '@/lib/business/holding-pipeline'
    );
    const tree = await loadHoldingSubtree(companyId);
    let query = supabase
      .from('opportunities')
      .select('*')
      .in('profile_id', tree.ids)
      .order('updated_at', { ascending: false })
      .limit(2000);
    if (stage && stage !== 'all') {
      query = query.or(`stage.eq.${stage},status.eq.${stage}`);
    }

    const { data, error } = await query;
    if (error) {
      return NextResponse.json({
        success: true,
        opportunities: [],
        warning: error.message,
        hint: 'Run 20260709_crm_leads_opportunities.sql',
      });
    }

    let opportunities: OpportunityListItem[] = (data || []).map((raw) => {
      const o = raw as Record<string, unknown>;
      const st = normalizeStage(
        o.stage as string | null,
        o.status as string | null
      );
      const amount = Number(o.amount ?? o.opportunity_size ?? 0);
      const probability =
        o.probability != null ? Number(o.probability) : stageProbability(st);
      const openDate =
        toDateOnly(o.open_date as string | null) ||
        toDateOnly(o.created_at as string | null) ||
        null;
      const expectedClose =
        toDateOnly(o.expected_close_date as string | null) ||
        toDateOnly(o.estimated_date as string | null) ||
        null;
      const actualClose = toDateOnly(o.actual_close_date as string | null);
      const annotated = annotateGroupOpportunity(
        { ...o, stage: st, amount, probability },
        companyId,
        tree.names
      );
      return {
        ...o,
        ...annotated,
        name: o.name ?? null,
        contact_name: o.contact_name ?? null,
        company_name: o.company_name ?? null,
        contact_email: o.contact_email ?? null,
        product_interest: o.product_interest ?? null,
        stage: st,
        amount,
        probability,
        open_date: openDate,
        expected_close_date: expectedClose,
        actual_close_date: actualClose,
        contact_phone: o.contact_phone || o.contact_number || null,
        location: o.location || o.opportunity_location || null,
        description: o.description || o.notes || null,
        weighted_amount: Math.round((amount * probability) / 100),
        days_to_expected:
          openDate && expectedClose
            ? Math.round(
                (new Date(expectedClose).getTime() -
                  new Date(openDate).getTime()) /
                  (24 * 60 * 60 * 1000)
              )
            : null,
        days_to_close:
          openDate && actualClose
            ? Math.round(
                (new Date(actualClose).getTime() -
                  new Date(openDate).getTime()) /
                  (24 * 60 * 60 * 1000)
              )
            : null,
        days_open:
          openDate && !actualClose
            ? Math.round(
                (Date.now() - new Date(openDate).getTime()) /
                  (24 * 60 * 60 * 1000)
              )
            : openDate && actualClose
              ? Math.round(
                  (new Date(actualClose).getTime() -
                    new Date(openDate).getTime()) /
                    (24 * 60 * 60 * 1000)
                )
              : null,
      };
    });

    if (q) {
      opportunities = opportunities.filter((o) => {
        const hay = [
          searchHay(o.name),
          searchHay(o.contact_name),
          searchHay(o.company_name),
          searchHay(o.contact_email),
          searchHay(o.contact_phone),
          searchHay(o.stage),
          searchHay(o.product_interest),
        ]
          .join(' ')
          .toLowerCase();
        return hay.includes(q);
      });
    }

    const { summarizeGroupPipeline } = await import(
      '@/lib/business/group-pipeline-view'
    );
    const group = summarizeGroupPipeline({
      viewerCompanyId: companyId,
      names: tree.names,
      companyIds: tree.ids,
      isSubsidiary: tree.isSubsidiary,
      opportunities,
    });

    return NextResponse.json({
      success: true,
      opportunities,
      group,
    });
  } catch (e: unknown) {
    return NextResponse.json({ error: e instanceof Error ? e.message : 'Error' }, { status: 500 });
  }
}
