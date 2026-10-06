package report

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// A dependency-free DOM fixture checks shell behavior where a browser binary
// is unavailable. All API values are synthetic, including the secret-shaped
// detail; it is never sent to a live tenant or third party.
func TestServerShellPaginationAndSafeLazyDOM(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	page, err := os.ReadFile("server.html")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, "-e", shellDOMFixture)
	cmd.Stdin = strings.NewReader(string(page))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("shell fixture: %v\n%s", err, output)
	}
}

const shellDOMFixture = `
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const source=fs.readFileSync(0,'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
class Element {
 constructor(tag){this.tag=tag;this.children=[];this.events={};this.attrs={};this.value='';this.textContent='';this.hidden=false;this.open=false;this.dataset={};this.isConnected=true;}
 append(...items){for(const x of items){if(x.tag==='fragment')this.children.push(...x.children);else this.children.push(x)}}
 replaceChildren(...items){this.children=[];this.append(...items)}
 addEventListener(name,fn){this.events[name]=fn}
 setAttribute(name,value){this.attrs[name]=value}
 get firstChild(){return this.children[0]}
 set innerHTML(v){throw new Error('Untrusted innerHTML is forbidden')}
}
const ids={};for(const id of ['categories','summary','module','project','severity','page-size','query','status','findings','findings-table','page-count','previous','next','filters','reset','coverage-panel','coverage','runs-panel','runs','export-json','export-assets'])ids[id]=new Element(id);
ids['page-size'].value='50';
const calls=[],timers=new Map();let nextTimer=0;
const context={document:{getElementById:id=>ids[id],createElement:tag=>new Element(tag),createDocumentFragment:()=>new Element('fragment')},URLSearchParams,AbortController,console,
 setTimeout:(fn,ms)=>{assert.equal(ms,300);timers.set(++nextTimer,fn);return nextTimer},clearTimeout:id=>timers.delete(id),
 fetch:async(path,options)=>{assert.equal(options.cache,'no-store');calls.push(path);let body;const u=new URL(path,'http://localhost');
 if(u.pathname==='/api/summary')body={categories:[{key:'best_practices',count:105}],modules:[{module:'fixture',category:'best_practices',count:105}],projects:['projects/123'],severity:{HIGH:105}};
 else if(u.pathname==='/api/findings'){const page=Number(u.searchParams.get('page'));const search=u.searchParams.get('q');const n=search?1:Math.min(50,105-(page-1)*50);body={findings:Array.from({length:n},(_,i)=>({id:(page-1)*50+i+1,project:'projects/123',module:'fixture',severity:'HIGH',title:'Synthetic finding',resource:'<img onerror=malicious>',resource_name:i===0?'api':i===1?'api_v1':'',resource_identity:i===0?'//cloudfunctions.googleapis.com/projects/123/locations/us-central1/functions/api':i===1?'//cloudfunctions.googleapis.com/projects/123/locations/us-central1/functions/api_v1':'<img onerror=malicious>'})),total:search?1:105,page,page_size:50};}
 else if(u.pathname.startsWith('/api/findings/'))body={detail:'{"value":"SYNTHETIC_VALIDATION_ONLY","html":"<script>malicious</script>"}',raw_output_path:'secret-hits/0123456789abcdef0123456789abcdef.txt'};
 else if(u.pathname==='/api/coverage')body={coverage:[{source:'fixture',status:'ok',count:1,error:''}],total:51,page:Number(u.searchParams.get('page')),page_size:50};
 else if(u.pathname==='/api/runs')body={runs:[{project:'assessment',module:'fixture',status:'completed',error:''}],total:1,page:1,page_size:50};
 else throw Error(path);return {ok:true,json:async()=>body};}};
vm.createContext(context);vm.runInContext(source,context);
const settle=()=>new Promise(resolve=>setImmediate(resolve));
(async()=>{
 await settle();assert.equal(ids.findings.children.length,100);assert.equal(ids['page-count'].textContent,'Page 1 of 3 • 105 matching findings');assert.equal(calls.filter(x=>/findings\//.test(x)).length,0);
 await ids.next.events.click();await settle();assert.match(ids['page-count'].textContent,/Page 2 of 3/);
 const tr=ids.findings.children[0],detail=ids.findings.children[1];const toggle=tr.children[4].children[1];assert.equal(tr.children.length,6);assert.equal(tr.children[3].textContent,'api');assert.match(tr.children[3].title,/functions\/api$/);assert.equal(ids.findings.children[2].children[3].textContent,'api_v1');assert.equal(ids.findings.children[4].children[3].textContent,'—');assert.equal(calls.filter(x=>/findings\//.test(x)).length,0);await toggle.events.click();assert.equal(detail.hidden,false);assert.equal(detail.children[0].colSpan,6);assert.match(detail.children[0].children[0].textContent,/SYNTHETIC_VALIDATION_ONLY/);assert.equal(detail.children[0].children[1].href,'/secret-hits/0123456789abcdef0123456789abcdef.txt');
 assert.equal(ids.findings.children[4].children[5].textContent,'<img onerror=malicious>');
 ids.query.value='searched';ids.query.events.input();assert.equal(timers.size,1);[...timers.values()][0]();await settle();assert.equal(ids.findings.children.length,2);assert.match(ids['page-count'].textContent,/Page 1 of 1/);
 ids['coverage-panel'].open=true;await ids['coverage-panel'].events.toggle();await settle();const pager=ids.coverage.children.at(-1);assert.equal(pager.children[2].disabled,false);await pager.children[2].events.click();await settle();assert(calls.includes('/api/coverage?page=2&page_size=50'));
 ids['runs-panel'].open=true;await ids['runs-panel'].events.toggle();await settle();assert.match(ids.runs.children[0].textContent,/assessment \/ fixture • completed/);
 assert(vm.runInContext("artifactLink('../engagement.db')===null && artifactLink('https://evil.example')===null",context));
 ids.module.value='fixture';ids.project.value='projects/123';ids.severity.value='HIGH';ids.query.value='<img onerror=bad>& secret';const beforeExport=calls.length;ids.query.events.input();
 for(const [id,path] of [['export-json','/api/export/json'],['export-assets','/api/export/assets']]){const url=new URL(ids[id].href,'http://localhost');assert.equal(url.origin,'http://localhost');assert.equal(url.pathname,path);assert.equal(url.searchParams.get('category'),'best_practices');assert.equal(url.searchParams.get('module'),'fixture');assert.equal(url.searchParams.get('project'),'projects/123');assert.equal(url.searchParams.get('severity'),'HIGH');assert.equal(url.searchParams.get('q'),'<img onerror=bad>& secret');assert.equal(url.searchParams.has('page'),false);assert.equal(url.searchParams.has('page_size'),false);await ids[id].events.click();}
 assert.equal(calls.length,beforeExport);ids.query.value='immediate click query';await ids['export-json'].events.click();assert.equal(new URL(ids['export-json'].href,'http://localhost').searchParams.get('q'),'immediate click query');assert.equal(calls.length,beforeExport);
 const originalFetch=context.fetch;let releaseStale;context.fetch=async(path,options)=>{const response=await originalFetch(path,options);if(path.includes('q=stale')){await new Promise(resolve=>releaseStale=resolve);return {ok:true,json:async()=>({findings:[],total:99,page:1,page_size:50})}}return response;};
 const stale=vm.runInContext("$('query').value='stale';loadPage()",context);await settle();await vm.runInContext("$('query').value='newest';loadPage()",context);releaseStale();await stale;assert.equal(vm.runInContext('state.total',context),1);assert.equal(ids.findings.children.length,2);
 assert(calls.every(x=>x.startsWith('/api/')));assert(calls.filter(x=>x.startsWith('/api/findings?')).every(x=>x.includes('page_size=50')));
 console.log('paginated shell, lazy metadata/detail and safe text DOM verified');
})().catch(e=>{console.error(e);process.exitCode=1});
`
