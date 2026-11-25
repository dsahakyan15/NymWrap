// Independent M3 oracle: fixed test policy, packet bodies and core accounting.
import {createHash} from 'node:crypto';
const policy=[['poisson',3,14],['poisson',5,10],['constant',3,14],['constant',5,10]];
const sha=body=>createHash('sha256').update(body).digest('hex');
export function auditCoverWeek(week,bodies){
  if(week?.version!==1||week.simulated_days!==7||week.production_workspace!==true||
    week.scenarios?.length!==4||bodies.length!==100)throw Error('incomplete_cover_week');
  let index=16,real=0,decoy=0;
  const days=[];
  for(const [scenario,expected]of policy.entries()){
    const data=week.scenarios[scenario], [mode,maxRequests,maxSpend]=expected;
    if(data.mode!==mode||data.max_requests_per_day!==maxRequests||data.max_spend_microusd!==maxSpend||
      data.cost_upper_bound_microusd!==3||data.mean_interval_s!==60||data.days?.length!==7)throw Error('invalid_cover_policy');
    let previous=-1;
    const kinds=new Map([['real',new Set()],['decoy',new Set()]]);
    for(let day=0;day<7;day++){
      const record=data.days[day];
      if(record.day!==day||record.events?.length!==3||record.blocked_probes!==2)throw Error('missing_cover_day_or_exhaustion');
      let requests=0,reserved=0;
      for(const [slot,event]of record.events.entries()){
        const kind=(slot+day)%2===0?'real':'decoy',body=bodies[index];
        if(!Number.isSafeInteger(event.at)||event.at<day*86400||event.at>=(day+1)*86400||event.at<=previous||
          mode==='constant'&&event.at<Math.max(previous+60,60))throw Error('cover_request_outside_slot');
        if(event.packet_index!==index||event.conversation!==index.toString(16).padStart(32,'0')||event.kind!==kind||
          event.bytes!==body.length||event.sha256!==sha(body))throw Error('cover_packet_mismatch');
        const parsed=JSON.parse(body.toString('utf8'));
        if(Object.keys(parsed).sort().join(',')!=='max_tokens,messages,model,stream,temperature'||parsed.model!=='synthetic'||
          parsed.max_tokens!==16||parsed.stream!==false||parsed.temperature!==0)throw Error('different_real_decoy_shape');
        requests++;reserved+=3;
        if(requests>maxRequests||reserved>maxSpend||event.usage?.day!==day||event.usage.requests!==requests||
          event.usage.reserved_microusd!==reserved)throw Error('cover_budget_exceeded_or_misreported');
        kinds.get(kind).add(body.length);if(kind==='real')real++;else decoy++;
        previous=event.at;index++;
      }
      if(record.usage?.day!==day||record.usage.requests!==requests||record.usage.reserved_microusd!==reserved||
        requests<maxRequests&&reserved+3<=maxSpend)throw Error('cover_budget_not_exercised');
      days.push({scenario,mode,day,requests,reserved_microusd:reserved,max_requests:maxRequests,max_spend_microusd:maxSpend});
    }
    for(const lengths of kinds.values())if(lengths.size!==5)throw Error('missing_real_decoy_bucket');
  }
  if(index!==bodies.length)throw Error('unaccounted_cover_packets');
  return {simulated_days:7,scenarios:4,requests:84,real_requests:real,decoy_requests:decoy,
    budget_exhaustion_probes:56,restart_accounting:true,days,wall_clock_packet_cadence_verified:false};
}
