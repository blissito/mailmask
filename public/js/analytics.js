// Google Analytics 4
(function(){
  var s = document.createElement('script');
  s.async = true;
  s.src = 'https://www.googletagmanager.com/gtag/js?id=G-KPH19KY0LJ';
  document.head.appendChild(s);
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', 'G-KPH19KY0LJ');
  window.gtag = gtag;
})();

// Microsoft Clarity
(function(c,l,a,r,i,t,y){
  c[a]=c[a]||function(){(c[a].q=c[a].q||[]).push(arguments)};
  t=l.createElement(r);t.async=1;t.src="https://www.clarity.ms/tag/"+i;
  y=l.getElementsByTagName(r)[0];y.parentNode.insertBefore(t,y);
})(window, document, "clarity", "script", "vkvqf6t3to");

// Campaña de origen: guarda los utm_* del primer toque 30 días para que el registro
// (con contraseña o con Google) los mande al servidor. Primer toque a propósito: si
// alguien llega por un anuncio y vuelve por Google, la campaña sigue siendo el anuncio.
(function(){
  try {
    var q = new URLSearchParams(location.search);
    var source = q.get("utm_source"), medium = q.get("utm_medium"), campaign = q.get("utm_campaign");
    if (!source && !medium && !campaign) return;
    var prev = null;
    try { prev = JSON.parse(localStorage.getItem("mailmask_utm") || "null"); } catch (e) {}
    if (prev && prev.at && Date.now() - prev.at < 30 * 864e5) return;
    localStorage.setItem("mailmask_utm", JSON.stringify({ source: source, medium: medium, campaign: campaign, at: Date.now() }));
  } catch (e) {}
})();
