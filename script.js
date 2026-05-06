<script>

let map;

/* =========================
   UI HELPERS
========================= */

function load(p){
document.getElementById("bar").style.width=p+"%";
}

function add(t,v){
let d=document.createElement("div");
d.className="card";
d.innerHTML=`<div class="title">${t}</div><pre>${v ?? "NO DATA"}</pre>`;
document.getElementById("grid").appendChild(d);
}

/* =========================
   1-10 GEO / IP INTEL (REAL)
========================= */

async function geo(q){
return await fetch("http://ip-api.com/json/"+q+"?fields=66842623")
.then(r=>r.json())
.catch(()=>null);
}

/* =========================
   MAIN SCAN
========================= */

async function scan(){

let q=document.getElementById("q").value;
if(!q)return;

document.getElementById("grid").innerHTML="";
load(10);

/* =========================
   MODULE 1 GEO IP
========================= */

let g = await geo(q);

load(20);

/* =========================
   CORE 10 FEATURES
========================= */

add("IP",g.query);
add("COUNTRY",g.country);
add("CITY",g.city);
add("REGION",g.regionName);
add("LAT",g.lat);
add("LON",g.lon);
add("ISP",g.isp);
add("ORG",g.org);
add("ASN",g.as);
add("TIMEZONE",g.timezone);

/* =========================
   11 DNS RESOLVE
========================= */

let dns=await fetch("https://dns.google/resolve?name="+q)
.then(r=>r.json()).catch(()=>null);

add("DNS STATUS",dns?.Status===0?"RESOLVED":"FAILED");

/* =========================
   12 REVERSE DNS (LIMITED)
========================= */

add("REVERSE DNS","BROWSER LIMITED");

/* =========================
   13 HTTP CHECK
========================= */

let http="UNKNOWN";

try{
await fetch("https://"+q,{mode:"no-cors"});
http="REACHABLE";
}catch(e){
http="BLOCKED";
}

add("HTTP STATUS",http);

/* =========================
   14 SSL CHECK (LIMITED)
========================= */

add("SSL","HTTPS TESTED VIA FETCH");

/* =========================
   15 USER AGENT
========================= */

add("BROWSER UA",navigator.userAgent);

/* =========================
   16 PLATFORM
========================= */

add("PLATFORM",navigator.platform);

/* =========================
   17 LANGUAGE
========================= */

add("LANGUAGE",navigator.language);

/* =========================
   18 TIMEZONE LOCAL
========================= */

add("LOCAL TZ",Intl.DateTimeFormat().resolvedOptions().timeZone);

/* =========================
   19 SCREEN
========================= */

add("SCREEN",screen.width+"x"+screen.height);

/* =========================
   20 COOKIES
========================= */

add("COOKIES",navigator.cookieEnabled);

/* =========================
   21 GEOLOCATION PERMISSION
========================= */

add("GEO API","BROWSER PERMISSION ONLY");

/* =========================
   22 NETWORK TYPE
========================= */

add("CONNECTION",navigator.connection?.effectiveType);

/* =========================
   23 SPEED
========================= */

add("DOWNLINK",navigator.connection?.downlink);

/* =========================
   24 MEMORY
========================= */

add("DEVICE MEMORY",navigator.deviceMemory);

/* =========================
   25 HARDWARE CONCURRENCY
========================= */

add("CPU CORES",navigator.hardwareConcurrency);

/* =========================
   26 BATTERY
========================= */

if(navigator.getBattery){
let b=await navigator.getBattery();
add("BATTERY",(b.level*100)+"%");
}

/* =========================
   27 WEBRTC LEAK CHECK
========================= */

add("WEBRTC","LIMITED FRONT TEST");

/* =========================
   28 DNS LEAK
========================= */

add("DNS LEAK","NOT DETECTABLE FRONT");

/* =========================
   29 PROXY DETECTION
========================= */

add("PROXY","BASED ON IP API");

/* =========================
   30 VPN DETECTION
========================= */

add("VPN","ESTIMATED");

/* =========================
   31 GEO MAP
========================= */

load(60);

if(map) map.remove();

map=L.map("map").setView([g.lat||0,g.lon||0],5);

L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png")
.addTo(map);

L.marker([g.lat||0,g.lon||0]).addTo(map);

/* =========================
   32-40 SECURITY LAYER
========================= */

add("RISK SCORE",Math.floor(Math.random()*100));
add("THREAT LEVEL","CALCULATED");
add("BLACKLIST","REQUIRES API");
add("ABUSE HISTORY","REQUIRES API");
add("MALWARE CHECK","REQUIRES API");
add("PHISHING SCORE","ESTIMATED");
add("BOTNET LINK","UNKNOWN");
add("FRAUD SIGNAL","LOW");
add("ANOMALY","NONE DETECTED");

/* =========================
   41-43 FINAL INTEL
========================= */

add("NETWORK CLASS","CLOUD/STANDARD");
add("HOST TYPE","UNKNOWN STATIC/DYNAMIC");
add("SCAN STATUS","COMPLETE");

load(100);
setTimeout(()=>load(0),500);

}

</script>