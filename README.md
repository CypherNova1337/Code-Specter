**Code Specter 👻**

A simple, powerful browser bookmarklet to scan the client-side source code of any webpage. It finds developer notes, keyword patterns, and performs basic taint analysis to find potential source-to-sink vulnerabilities.

Features

  One-Click Scan: Analyze any webpage with a single click from your bookmarks bar.

  Source-to-Sink Analysis: Detects potential data flows from user-controlled sources (like URL parameters) into dangerous functions (sinks) like .innerHTML.

  Finds Developer Notes: Searches for common developer annotations like TODO:, FIXME:, HACK:, and DEBUG.

  Prioritized Results: The UI clearly separates high-priority source-to-sink flows from lower-priority informational findings for efficient analysis.

  Fixed UI Controls: The "Close" button remains fixed to the corner of the screen, allowing you to easily close the results panel no matter how far you've scrolled.

  Updatable: Use the loader method to automatically get the latest version of the script without ever updating your bookmark.

⚠️ Important Disclaimer

This bookmarklet operates only on the client-side. It can only analyze the HTML, JavaScript, and CSS that your browser has received from the server. It uses pattern matching and heuristics to find potential issues; findings may include false positives and require manual verification. It cannot see actual server-side code.

Installation


Right-click your bookmarks bar and select Add page... (Chrome) or New Bookmark... (Firefox).

For Name, enter Code Specter.

For URL (or Location), copy and paste the full JavaScript code below:
    

    javascript:(async function(){function e(t){return t.replace(/[.*+?^${}()|[\]\\]/g,"\\$&")}const o=["location","document.referrer","window.name","history.state","searchParams"],n=["innerHTML","outerHTML","document.write","document.writeln"],s=["TODO:",": FIXME",": NOTE",": HACK",": XXX","DEBUG","eval(","assert(","system(","exec(","shell_exec(","passthru(","popen(","`","include(","require(","unserialize(","os.system(","pickle.loads(","yaml.load(","Marshal.load("];let r="";const i={keywords:{},taintFlows:[],allSinks:[]};function a(t){const c=document.createElement("div");c.innerHTML=`<div style="background-color:#fff; padding:20px; border-radius:8px; width:80%; max-width:800px; height:80%; overflow-y:auto; font-family:monospace; font-size:14px; color:#333; box-shadow:0 5px 15px rgba(0,0,0,0.3);"><h2 style="border-bottom:2px solid #eee; padding-bottom:10px;">Code Specter Results</h2><div>${t}</div></div><button id="codeScannerClose" style="position:fixed; top:20px; right:20px; z-index:10000; padding:8px 12px; border:none; border-radius:5px; background-color:#dc3545; color:white; cursor:pointer;">Close</button>`,c.style.position="fixed",c.style.top="0",c.style.left="0",c.style.width="100%",c.style.height="100%",c.style.backgroundColor="rgba(0,0,0,0.5)",c.style.zIndex="9999",c.style.display="flex",c.style.alignItems="center",c.style.justifyContent="center",document.body.appendChild(c),document.getElementById("codeScannerClose").onclick=()=>c.remove()}let l="";const d=[],p=document.querySelectorAll("script");p.forEach((t=>{t.src?d.push(fetch(t.src).then((c=>c.ok?c.text():Promise.resolve(""))).catch((c=>(console.warn(`Code Specter: Could not fetch ${t.src}`,c),"")))):l+=t.textContent+"\n"}));const u=await Promise.all(d);l+=u.join("\n");const g=document.documentElement.outerHTML;s.forEach((t=>{const c=new RegExp(e(t),"gi"),m=g.match(c);m&&(i.keywords[t]=m.length)}));const h=new RegExp(`(?:\\.|\\s*)(${n.join("|")})\\s*(=|\\()`,"g");let f;for(;(f=h.exec(l))!==null;){const t=f[1],c=l.substring(f.index,f.index+200),m=c.match(new RegExp(`${e(t)}\\s*(?:=|\\()\\s*['"]?([^;'"\\)]+)`));let y=!1;if(m&&m[1]){let b=m[1].trim();const w=e(b),S=new RegExp(`(var|let|const|\\s*)${w}\\s*=\s*([^;]+)`,"g");let k;for(;(k=S.exec(l))!==null;){const x=k[2],C=o.find((E=>x.includes(E)));if(C){const E={source:C,sink:t,flow:`...${k[0]}... -> ...${m[0]}...`};i.taintFlows.push(E),y=!0}}}y||i.allSinks.push({sink:t,source:null,flow:c.substring(0,70)+"..."})}r+="<h3>Keyword Matches</h3>",Object.keys(i.keywords).length>0?(r+="<ul>",Object.entries(i.keywords).forEach((([t,c])=>{r+=`<li><strong>${t}</strong>: ${c} found</li>`})),r+="</ul>"):r+="<p>No specific keywords found.</p>",r+="<hr><h3>Potential Source-to-Sink Flows</h3>",i.taintFlows.length>0?(r+=`<p>Direct flows from a known source to a known sink (High Priority).</p><ul>`,i.taintFlows.forEach((t=>{r+=`<li><strong>Source:</strong> <code style="color:green;">${t.source}</code><br><strong>Sink:</strong> <code style="color:red;">${t.sink}</code><br><strong>Flow Snippet:</strong> <pre><code>${t.flow.replace(/</g,"&lt;")}</code></pre></li>`})),r+="</ul>"):r+="<p>No direct source-to-sink flows were identified.</p>",r+="<hr><h3>All Identified Sinks (Verbose)</h3>",i.allSinks.length>0?(r+="<p>Every sink found, including those without a direct source.</p><ul>",i.allSinks.forEach((t=>{r+=`<li><strong>Source:</strong> <code style="color:grey;">❓ Not Found</code><br><strong>Sink:</strong> <code style="color:orange;">${t.sink}</code><br><span style="color:grey; font-style:italic;">Note: This is likely informational. Manual review is recommended.</span><br><strong>Sink Snippet:</strong> <pre><code>${t.flow.replace(/</g,"&lt;")}</code></pre></li>`})),r+="</ul>"):r+="<p>No known sinks were identified in the scanned scripts.</p>",a(r)})();

Save the bookmark.


How to Use

  Navigate to any webpage you want to analyze.

  Click the Code Specter bookmark.

  A modal window will appear with the results, broken into three sections:

  Keyword Matches: Simple matches for developer notes and keywords.

  Potential Source-to-Sink Flows: High-priority findings where user input (source) appears to flow into a dangerous function (sink).

  All Identified Sinks (Verbose): A full list of every sink found, even those without a direct source. These are lower-priority but may be useful for manual investigation.

  Click the Close button (fixed in the top-right corner of the screen) to dismiss the window.

What Code Specter Looks For

Taint Analysis Sources

The script looks for these sources of user input:

  location (e.g., location.href, location.search)

  document.referrer

  window.name

  history.state

  URLSearchParams

Taint Analysis Sinks

It traces sources into these dangerous sinks:

  .innerHTML

  .outerHTML

  document.write()

  document.writeln()

Keyword Patterns & Developer Notes

  Notes: TODO:, FIXME:, NOTE:, HACK:, XXX:, DEBUG

  PHP: eval(, assert(, system(, exec(, etc.

  Python: os.system(, pickle.loads(, yaml.load(
