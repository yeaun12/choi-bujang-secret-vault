// Stage 12 student-selected scenarios, NOT the official 41-case assault.
// No unexecuted scenario is pre-marked as passed. Metadata stays in memory.
const entries = [
 [1,'normal','app_public','공개 앱 페이지','GET /',200,'public'],
 [1,'denied','legacy_static','정적 메모 노출 차단','GET /data.json',404,'public'],
 [2,'normal','app_without_data','정적 파일 제거 후 앱','GET /',200],
 [2,'denied','data_unavailable','정적 메모 파일 제거','GET /data.json',404],
 [3,'normal','authenticated_notes','로그인 사용자 메모 읽기','GET /api/notes',200],
 [3,'denied','anonymous_notes','익명 메모 조회 차단','GET /api/notes',401,'anonymous'],
 [4,'normal','owned_note','본인 메모 조회','GET /api/notes/:id',200],
 [4,'denied','cross_owner','타인 메모 조회 차단','GET /api/notes/:id',404],
 [5,'normal','proxy_note','서버 경유 본인 메모','GET /api/notes',200],
 [5,'denied','direct_db','원본 DB 직접 조회 차단','원본 DB API','거부'],
 [6,'normal','registered_device','등록 기기 정책','ALEPH SDP 판정','allow'],
 [6,'denied','unregistered_device','미등록 기기 정책','ALEPH SDP 판정','deny'],
 [7,'normal','step_up_ok','재인증 확인 후 허용','ALEPH SDP 재확인','allow'],
 [7,'denied','step_up_needed','이상 접속 추가 확인','ALEPH SDP 판정','step_up'],
 [8,'normal','owned_zone','본인 자료 구역','GET /api/notes',200],
 [8,'denied','anonymous_notice','익명 강사 공지 거부','GET /api/instructor-notices',401,'anonymous'],
 [9,'normal','low_frequency','일반 조회 회수 미제안','탐지 사건 계약','observe'],
 [9,'denied','burst_candidate','과다 조회 회수 제안','탐지 사건 계약','propose_revocation'],
 [10,'normal','restored_b','검증된 B 메모 복구','POST /api/restore',200],
 [10,'denied','anonymous_restore','익명 복구 차단','POST /api/restore',401],
 [11,'normal','signed_notes','서명된 본인 메모 조회','GET /api/notes',200,'signed'],
 [11,'denied','unsigned_notes','서명 없는 학생 메모 요청','GET /api/notes',403,'unsigned'],
 [12,'normal','signed_war_room','서명된 작전실 조회','GET /api/war-room',200,'signed'],
 [12,'denied','anonymous_war_room','익명 작전실 조회','GET /api/war-room',401,'anonymous'],
];
export const SCENARIOS = Object.freeze(entries.map(
 ([stage,direction,id,label,request,expected,automation=null])=>
 Object.freeze({stage,direction,id,label,request,expected,automation})));
export function blankResults() {
 return SCENARIOS.map(s=>({...s,result:'not_executed',actual:null,requestId:null,
  requestIdSource:null,observedAt:null}));
}
export function recordResult(rows, {id,status,requestId,requestIdSource,observedAt}) {
 const row=rows.find(x=>x.id===id);
 if(!row)throw Error('unknown_check');
 if(!row.automation)throw Error('manual_check_cannot_be_measured');
 if(!/^[a-f0-9-]{36}$/iu.test(requestId||'')||
    !['client','server'].includes(requestIdSource)||
    !Number.isFinite(Date.parse(observedAt)))throw Error('invalid_metadata');
 const actual=Number.isInteger(status)&&status>=100&&status<=599?status:null;
 return rows.map(x=>x.id===id?{...x,actual,requestId,requestIdSource,observedAt,
   result:actual===null?'request_error':actual===x.expected?'matched':'mismatch'}:x);
}
export function summarizeResults(rows) {
 const measured=rows.filter(x=>['matched','mismatch'].includes(x.result));
 return {total:rows.length,measured:measured.length,matched:measured.filter(x=>x.result==='matched').length,
  mismatched:measured.filter(x=>x.result==='mismatch').length,
  allowedObserved:measured.some(x=>x.direction==='normal'&&x.result==='matched'),
  deniedObserved:measured.some(x=>x.direction==='denied'&&x.result==='matched'),
  official41:'unverified'};
}
