/* Daily Security Briefing — 인터랙션 (의존성 없음)
 * 보안: innerHTML 을 쓰지 않고 textContent / createElement 만 사용한다.
 * 성능: transform/opacity 만 바꾸고, 스크롤 처리는 rAF 로 묶는다.
 */
(() => {
  "use strict";

  /* ---------- 0. 클릭재킹 방어 (OWASP A04/A05) ----------
   * GitHub Pages 는 X-Frame-Options / CSP frame-ancestors 헤더를 설정할 수 없어서,
   * 다른 사이트가 이 페이지를 투명 iframe 으로 덮어씌우지 못하게 JS 로 막는다. */
  if (window.top !== window.self) {
    document.documentElement.style.display = "none";
    try { window.top.location.replace(window.self.location.href); } catch { /* 교차 출처면 그냥 숨김 유지 */ }
    return;
  }
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const readJSON = (id) => {
    const el = document.getElementById(id);
    if (!el) return null;
    try { return JSON.parse(el.textContent); } catch { return null; }
  };

  /* ---------- 1. 스크롤: nav 경계선, 읽기 진행률 ---------- */
  const nav = $(".nav");
  const bar = $(".progress__bar");
  let ticking = false;
  const onScroll = () => {
    const y = window.scrollY;
    nav && nav.classList.toggle("is-scrolled", y > 8);
    if (bar) {
      const max = document.documentElement.scrollHeight - innerHeight;
      bar.style.transform = `scaleX(${max > 0 ? Math.min(1, y / max) : 0})`;
    }
    pipeProgress();
    ticking = false;
  };
  addEventListener("scroll", () => { if (!ticking) { ticking = true; requestAnimationFrame(onScroll); } }, { passive: true });

  /* ---------- 2. 등장 애니메이션 (화면 밖 요소에만 적용 → 깜빡임 없음) ---------- */
  const revealEls = $$("[data-reveal], .card, .row, .fact");
  if (!reduce && "IntersectionObserver" in window) {
    const io = new IntersectionObserver((entries) => {
      entries.forEach((e) => {
        if (e.isIntersecting) { e.target.classList.add("is-in"); io.unobserve(e.target); }
      });
    }, { rootMargin: "0px 0px -8% 0px" });
    revealEls.forEach((el) => {
      const r = el.getBoundingClientRect();
      if (r.top > innerHeight) {
        // 같은 줄의 형제 요소끼리 순차 등장 (stagger)
        const idx = Array.prototype.indexOf.call(el.parentElement.children, el) % 6;
        el.style.setProperty("--d", `${idx * 70}ms`);
        el.classList.add("will-reveal");
        io.observe(el);
      } else {
        el.classList.add("is-in");
      }
    });
  } else {
    revealEls.forEach((el) => el.classList.add("is-in"));
  }

  /* ---------- 3. 카드 스포트라이트 (커서 위치) ---------- */
  if (!reduce && matchMedia("(hover: hover)").matches) {
    $$(".card").forEach((card) => {
      card.addEventListener("pointermove", (e) => {
        const r = card.getBoundingClientRect();
        card.style.setProperty("--mx", `${e.clientX - r.left}px`);
        card.style.setProperty("--my", `${e.clientY - r.top}px`);
      });
    });
  }

  /* ---------- 4. 숫자 카운트업 ---------- */
  const countUp = (el) => {
    const target = parseInt(el.dataset.count, 10);
    if (!Number.isFinite(target) || reduce || target === 0) { el.textContent = String(target || 0); return; }
    const dur = 1100, t0 = performance.now();
    const step = (t) => {
      const p = Math.min(1, (t - t0) / dur);
      el.textContent = String(Math.round(target * (1 - Math.pow(1 - p, 4))));
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  };

  /* ---------- 5. 아카이브 데이터 → 연속 발행일 + 히트맵 ---------- */
  const archive = readJSON("archive-data");
  if (archive) {
    const DAY = 864e5;
    const kstToday = () => {
      const now = new Date(Date.now() + 9 * 36e5);
      return Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
    };
    const parse = (s) => { const [y, m, d] = s.split("-").map(Number); return Date.UTC(y, m - 1, d); };
    const byDay = new Map();
    archive.forEach((p) => { if (typeof p.d === "string" && /^\d{4}-\d{2}-\d{2}$/.test(p.d)) byDay.set(parse(p.d), p); });

    // 연속 발행: 오늘(또는 아직 발행 전이면 어제)부터 거꾸로
    const streakEl = $("[data-streak]");
    if (streakEl) {
      let day = kstToday();
      if (!byDay.has(day)) day -= DAY;
      let n = 0;
      while (byDay.has(day)) { n++; day -= DAY; }
      streakEl.dataset.count = String(n);
    }

    // 히트맵: 최근 26주, 열 = 주(일~토)
    const grid = $("[data-heatmap] .heat__grid");
    if (grid) {
      const today = kstToday();
      const weeks = 26;
      const start = today - (new Date(today).getUTCDay() + (weeks - 1) * 7) * DAY;
      const frag = document.createDocumentFragment();
      for (let t = start; t <= today; t += DAY) {
        const p = byDay.get(t);
        const label = new Date(t).toISOString().slice(0, 10);
        let cell;
        if (p && typeof p.u === "string" && p.u.startsWith("/") && !p.u.startsWith("//")) {
          cell = document.createElement("a");
          cell.href = p.u;
          const s = Math.min(5, Math.max(1, parseInt(p.s, 10) || 1));
          cell.dataset.sev = String(s);
          cell.setAttribute("aria-label", `${label} 브리핑, 위협 수준 ${s}`);
          cell.title = `${label} · 위협 수준 ${s}/5`;
        } else {
          cell = document.createElement("span");
          cell.setAttribute("aria-label", `${label} 발행 없음`);
        }
        cell.className = "heat__cell" + (t === today ? " is-today" : "");
        cell.setAttribute("role", "listitem");
        frag.appendChild(cell);
      }
      grid.appendChild(frag);
      const heat = grid.parentElement;
      heat.scrollLeft = heat.scrollWidth;
    }
  }

  // 카운트업은 화면에 보일 때 시작
  const counters = $$("[data-count]");
  if ("IntersectionObserver" in window) {
    const cio = new IntersectionObserver((es) => es.forEach((e) => {
      if (e.isIntersecting) { countUp(e.target); cio.unobserve(e.target); }
    }), { threshold: .6 });
    counters.forEach((c) => cio.observe(c));
  } else counters.forEach(countUp);

  /* ---------- 6. 브리핑: 레일 활성화 ---------- */
  const issues = $$(".issue");
  const railLinks = $$(".rail a");
  if (issues.length && "IntersectionObserver" in window) {
    const rio = new IntersectionObserver((es) => {
      es.forEach((e) => {
        if (!e.isIntersecting) return;
        issues.forEach((s) => s.classList.toggle("is-active", s === e.target));
        const id = e.target.id;
        railLinks.forEach((a) => {
          const on = a.getAttribute("href") === `#${id}`;
          a.classList.toggle("is-active", on);
          if (on) a.setAttribute("aria-current", "true"); else a.removeAttribute("aria-current");
        });
      });
    }, { rootMargin: "-45% 0px -50% 0px" });
    issues.forEach((s) => rio.observe(s));
  }

  /* ---------- 7. 툴팁: 본문 속 보안 용어 + 지표 ⓘ 버튼 ---------- */
  const terms = readJSON("terms-data") || [];
  const metrics = readJSON("metrics-data") || {};
  const TRIGGER = ".term, .info";
  const tip = document.createElement("div");
  tip.className = "tip";
  tip.id = "term-tip";
  tip.setAttribute("role", "tooltip");
  document.body.appendChild(tip);
  let openBtn = null;

  // 버튼 → {title, sub, body}. 모든 값은 textContent 로만 넣는다.
  const contentFor = (btn) => {
    if (btn.classList.contains("info")) {
      const key = btn.dataset.info;
      const m = Object.prototype.hasOwnProperty.call(metrics, key) ? metrics[key] : null;
      return m && { title: m.title, sub: m.sub, body: m.body };
    }
    const t = terms[Number(btn.dataset.idx)];
    return t && { title: t.term, sub: t.english, body: t.definition };
  };

  const show = (btn) => {
    const c = contentFor(btn);
    if (!c) return;
    const b = document.createElement("b");
    b.textContent = String(c.title || "");
    const sub = document.createElement("span");
    sub.className = "tip__sub";
    sub.textContent = String(c.sub || "");
    const d = document.createElement("p");
    d.textContent = String(c.body || "");
    tip.replaceChildren(b, sub, d);
    tip.classList.add("is-open");
    const r = btn.getBoundingClientRect();
    const w = tip.offsetWidth || 320;
    const left = Math.max(16, Math.min(scrollX + r.left + r.width / 2 - w / 2, scrollX + innerWidth - w - 16));
    const below = r.bottom + 10 + tip.offsetHeight < innerHeight;
    tip.style.left = `${left}px`;
    tip.style.top = `${scrollY + (below ? r.bottom + 10 : r.top - tip.offsetHeight - 10)}px`;
    if (openBtn && openBtn !== btn) openBtn.setAttribute("aria-expanded", "false");
    btn.setAttribute("aria-expanded", "true");
    openBtn = btn;
  };
  const hide = () => {
    tip.classList.remove("is-open");
    if (openBtn) openBtn.setAttribute("aria-expanded", "false");
    openBtn = null;
  };

  if (Array.isArray(terms) && terms.length) {
    const used = new Set();
    const keys = terms
      .map((t, i) => ({ i, k: String(t.term || "").trim() }))
      .filter((x) => x.k.length >= 2)
      .sort((a, b) => b.k.length - a.k.length);

    $$("[data-terms]").forEach((p) => {
      keys.forEach(({ i, k }) => {
        if (used.has(i)) return;
        const walker = document.createTreeWalker(p, NodeFilter.SHOW_TEXT);
        let node;
        while ((node = walker.nextNode())) {
          if (node.parentElement.closest(".term")) continue;
          const at = node.nodeValue.indexOf(k);
          if (at < 0) continue;
          const after = node.splitText(at);
          after.splitText(k.length);
          const btn = document.createElement("button");
          btn.type = "button";
          btn.className = "term";
          btn.dataset.idx = String(i);
          btn.setAttribute("aria-describedby", "term-tip");
          btn.setAttribute("aria-expanded", "false");
          btn.textContent = k;
          after.replaceWith(btn);
          used.add(i);
          break;
        }
      });
    });

  }

  const hoverable = matchMedia("(hover: hover)");
  document.addEventListener("click", (e) => {
    const btn = e.target.closest && e.target.closest(TRIGGER);
    if (btn) { e.preventDefault(); e.stopPropagation(); openBtn === btn ? hide() : show(btn); } else hide();
  });
  document.addEventListener("pointerover", (e) => {
    const btn = e.target.closest && e.target.closest(TRIGGER);
    if (btn && hoverable.matches) show(btn);
  });
  document.addEventListener("pointerout", (e) => {
    if (e.target.closest && e.target.closest(TRIGGER) && hoverable.matches) hide();
  });
  document.addEventListener("focusin", (e) => { if (e.target.matches && e.target.matches(TRIGGER)) show(e.target); });
  document.addEventListener("focusout", (e) => { if (e.target.matches && e.target.matches(TRIGGER)) hide(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") hide(); });
  addEventListener("resize", hide);

  /* ---------- 8. About: 파이프라인 선 그리기 ---------- */
  const pipe = $(".pipe");
  function pipeProgress() {
    if (!pipe) return;
    const r = pipe.getBoundingClientRect();
    const p = Math.min(1, Math.max(0, (innerHeight * 0.7 - r.top) / r.height));
    pipe.style.setProperty("--p", reduce ? 1 : p.toFixed(3));
  }

  /* ---------- 9. 용어 사전: 검색 + 첫 글자 필터 ---------- */
  const list = $("#term-list");
  if (list) {
    const cards = $$(".tcard", list);
    const input = $("#term-search");
    const filter = $("#term-filter");
    const empty = $("#term-empty");
    const CHO = ["ㄱ", "ㄲ", "ㄴ", "ㄷ", "ㄸ", "ㄹ", "ㅁ", "ㅂ", "ㅃ", "ㅅ", "ㅆ", "ㅇ", "ㅈ", "ㅉ", "ㅊ", "ㅋ", "ㅌ", "ㅍ", "ㅎ"];
    const NORM = { "ㄲ": "ㄱ", "ㄸ": "ㄷ", "ㅃ": "ㅂ", "ㅆ": "ㅅ", "ㅉ": "ㅈ" };
    const initial = (s) => {
      const c = s.trim().charAt(0);
      const code = c.charCodeAt(0) - 0xac00;
      if (code >= 0 && code < 11172) { const ch = CHO[Math.floor(code / 588)]; return NORM[ch] || ch; }
      return /[a-z]/i.test(c) ? "A-Z" : "#";
    };
    cards.forEach((c) => { c.dataset.init = initial(c.dataset.term || ""); });
    const inits = [...new Set(cards.map((c) => c.dataset.init))].sort((a, b) => a.localeCompare(b, "ko"));
    let active = "";
    ["전체", ...inits].forEach((label) => {
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = label;
      b.setAttribute("aria-pressed", label === "전체" ? "true" : "false");
      b.addEventListener("click", () => {
        active = label === "전체" ? "" : label;
        $$("button", filter).forEach((x) => x.setAttribute("aria-pressed", x === b ? "true" : "false"));
        apply();
      });
      filter.appendChild(b);
    });
    const apply = () => {
      const q = (input.value || "").trim().toLowerCase();
      let shown = 0;
      cards.forEach((c) => {
        const ok = (!active || c.dataset.init === active) && (!q || c.textContent.toLowerCase().includes(q));
        c.hidden = !ok;
        if (ok) shown++;
      });
      empty.hidden = shown > 0;
    };
    input.addEventListener("input", apply);
  }

  onScroll();
})();
