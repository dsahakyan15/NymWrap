// Index ranges partition cases; they never partition one conversation or its history.
export function shardRange(total,index,count){
  if(!Number.isSafeInteger(total)||total<1||!Number.isSafeInteger(count)||count<2||count>16||count>total||
    !Number.isSafeInteger(index)||index<0||index>=count)throw Error('invalid_linkcheck_shard');
  return {index,count,start:Math.floor(total*index/count),end:Math.floor(total*(index+1)/count)};
}
