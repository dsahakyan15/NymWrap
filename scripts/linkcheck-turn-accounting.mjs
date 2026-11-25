// A captured request is disclosed even if its reply fails. It is not another
// attempted turn: count successful replies + refused turns, not disclosures.
export function phaseMetrics(report,corpus){
  const rows=report.observations,cases=new Map(corpus.cases.map(item=>[item.id,item]));
  if(!rows.length||cases.size!==rows.length||new Set(rows.map(row=>row.id)).size!==rows.length)throw Error('turn_accounting_requires_exact_known_subset');
  let attempted=0,unattempted=0,replies=0,remoteReplies=0;
  for(const row of rows){
    const expected=cases.get(row.id),ok=row.local_reasons?.length;
    if(!expected||!Number.isSafeInteger(ok)||row.local_turns>ok||ok+row.blocked_turns>expected.turns.length||row.remote_turns<ok-row.local_turns)throw Error('inconsistent_turn_accounting');
    replies+=ok;remoteReplies+=ok-row.local_turns;attempted+=ok+row.blocked_turns;
    unattempted+=expected.turns.length-ok-row.blocked_turns;
  }
  const count=key=>rows.reduce((n,row)=>n+row[key],0),turns=corpus.cases.reduce((n,item)=>n+item.turns.length,0);
  return {accounting_version:2,cases:rows.length,turns,attempted_turns:attempted,successful_reply_turns:replies,
    successful_remote_reply_turns:remoteReplies,remote_turns:count('remote_turns'),l0_turns:count('local_turns'),refused_turns:count('blocked_turns'),
    disclosed_without_successful_remote_reply:count('remote_turns')-remoteReplies,unattempted_turns:unattempted,
    l0_only_cases:rows.filter(row=>row.local_turns>0&&row.remote_turns===0).length,l0_case_fraction:rows.filter(row=>row.local_turns>0).length/rows.length,
    l0_turn_fraction:count('local_turns')/turns,
    by_language:Object.fromEntries(['en','ru','hy'].map(language=>[language,{cases:rows.filter(row=>row.language===language).length,
      l0_turns:rows.filter(row=>row.language===language).reduce((n,row)=>n+row.local_turns,0),turns:corpus.cases.filter(item=>item.language===language).reduce((n,item)=>n+item.turns.length,0)}]))};
}
