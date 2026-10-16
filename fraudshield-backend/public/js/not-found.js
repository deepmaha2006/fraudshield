// not-found.js — animated status page for three situations:
//   notfound : the page does not exist (served by the server with HTTP 404)
//   offline  : no network / server unreachable (served from the service-worker cache)
//   error    : the server failed (HTTP 500 / proxy 502–504)
// Self-contained (no CDN, no fonts) so it renders with no connection at all.

(() => {
    const body = document.body;
    const prefersStatic = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // ------------------------------------------------------------ variant & copy
    let variant = body.dataset.variant || 'notfound';
    // A 404 page shown while the device is offline is really an offline problem.
    if (variant === 'notfound' && navigator.onLine === false) variant = 'offline';

    const COPY = {
        notfound: {
            title: 'Page Not Found',
            code: '404',
            text: 'The page you are looking for might have been removed, had its name changed, or is temporarily unavailable.',
        },
        offline: {
            title: 'Connection Lost',
            code: 'Offline',
            text: navigator.onLine === false
                ? 'Your device is not connected to the internet. FraudShield will reconnect automatically when the network is back.'
                : 'The FraudShield server cannot be reached right now. It may be restarting or the network between you and it is down.',
        },
        error: {
            title: 'Something Went Wrong',
            code: '500',
            text: 'The server hit an unexpected error while loading this page. Nothing you did caused it — try again in a moment.',
        },
    };
    const copy = COPY[variant] || COPY.notfound;
    document.title = `${copy.code} · ${copy.title} — FraudShield`;
    document.getElementById('nf-title').textContent = copy.title;
    document.getElementById('nf-code').textContent = copy.code;
    document.getElementById('nf-text').textContent = copy.text;

    // ------------------------------------------------------------ safe "try again" target
    // Only same-origin paths are accepted, so ?return= cannot become an open redirect.
    function safeReturnPath() {
        const ownPages = ['/404.html', '/offline.html', '/500.html'];
        let candidate = new URLSearchParams(location.search).get('return');
        // Served by the service worker in place of another page: retry that page.
        if (!candidate && !ownPages.includes(location.pathname)) candidate = location.pathname + location.search;
        if (!candidate) return null;
        try {
            const url = new URL(candidate, location.origin);
            if (url.origin !== location.origin || !url.pathname.startsWith('/') || ownPages.includes(url.pathname)) return null;
            return url.pathname + url.search;
        } catch {
            return null;
        }
    }
    const retryTo = safeReturnPath();
    if (retryTo && variant !== 'notfound') {
        const detail = document.getElementById('nf-detail');
        detail.textContent = `While opening ${retryTo}`;
        detail.hidden = false;
    }

    // ------------------------------------------------------------ actions
    const btnBack = document.getElementById('nf-back');
    const btnHome = document.getElementById('nf-home');
    const btnRetry = document.getElementById('nf-retry');

    btnBack.addEventListener('click', () => {
        if (history.length > 1 && document.referrer && new URL(document.referrer).origin === location.origin) history.back();
        else location.href = '/';
    });
    btnHome.addEventListener('click', () => { location.href = '/'; });

    const retry = () => {
        if (retryTo) location.replace(retryTo);
        else location.reload();
    };
    if (variant === 'notfound') {
        btnRetry.hidden = true;
    } else {
        btnRetry.hidden = false;
        btnRetry.addEventListener('click', retry);
        // Come back automatically once the network returns.
        window.addEventListener('online', () => setTimeout(retry, 800));
    }

    // ------------------------------------------------------------ message fade-in
    const message = document.getElementById('nf-message');
    if (prefersStatic) {
        body.classList.add('nf-static');
        message.classList.add('visible');
        return; // no animations at all
    }
    setTimeout(() => message.classList.add('visible'), 1200);

    // ------------------------------------------------------------ stick figures (drawn locally)
    // Inline data: images — no third-party requests, and <img>-loaded SVG can never run script.
    const INK = '#0b0f14';
    const svg = inner => `data:image/svg+xml,${encodeURIComponent(
        `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" fill="none" stroke="${INK}" stroke-width="5" stroke-linecap="round" stroke-linejoin="round">${inner}</svg>`)}`;
    const POSES = {
        run: svg('<circle cx="50" cy="17" r="9"/><path d="M50 26v32M50 36l-18 12M50 36l20-6M50 58l-16 24M50 58l16 20 8 12"/>'),
        star: svg('<circle cx="50" cy="15" r="9"/><path d="M50 24v34M50 35L22 23M50 35l28-12M50 58L28 88M50 58l22 30"/>'),
        flail: svg('<circle cx="50" cy="20" r="9"/><path d="M50 29v29M50 36L36 8M50 36l14-28M50 58l-20 10 6 20M50 58l18 16-10 14"/>'),
        sit: svg('<circle cx="34" cy="32" r="9"/><path d="M36 41l6 26h26v22M40 50l24 10"/><path d="M62 54h24l-6 14H62z" fill="' + INK + '"/>'),
    };

    const FIGURES = [
        { top: '0%', src: POSES.run, transform: 'rotateZ(-90deg)', speedX: 1500 },
        { top: '10%', src: POSES.star, speedX: 3000, speedRotation: 2000 },
        { top: '20%', src: POSES.flail, speedX: 5000, speedRotation: 1000 },
        { top: '25%', src: POSES.run, speedX: 2500, speedRotation: 1500 },
        { top: '35%', src: POSES.star, speedX: 2000, speedRotation: 300 },
        { bottom: '5%', src: POSES.sit, speedX: 0 }, // stays put
    ];

    const characters = document.getElementById('nf-characters');
    function runCharacters() {
        characters.replaceChildren();
        FIGURES.forEach((f, index) => {
            const img = document.createElement('img');
            img.alt = '';
            img.src = f.src;
            if (f.top) img.style.top = f.top;
            if (f.bottom) img.style.bottom = f.bottom;
            if (f.transform) img.style.transform = f.transform;
            characters.appendChild(img);
            if (!f.speedX) return;
            img.animate([{ left: '100%' }, { left: '-20%' }], { duration: f.speedX, easing: 'linear', fill: 'forwards' });
            if (index > 0 && f.speedRotation) {
                img.animate([{ transform: 'rotate(0deg)' }, { transform: 'rotate(-360deg)' }],
                    { duration: f.speedRotation, iterations: Infinity, easing: 'linear' });
            }
        });
    }

    // ------------------------------------------------------------ expanding circles (canvas)
    const canvas = document.getElementById('nf-canvas');
    const ctx = canvas.getContext('2d');
    let circles = [];
    let frame = 0;
    let rafId = 0;

    function initCircles() {
        circles = [];
        for (let i = 0; i < 300; i++) {
            const x = Math.floor(Math.random() * (canvas.width * 3 - canvas.width * 1.2 + 1)) + canvas.width * 1.2;
            const y = Math.floor(Math.random() * (canvas.height - (canvas.height * -0.2 + 1))) + canvas.height * -0.2;
            circles.push({ x, y, size: canvas.width / 1000 });
        }
    }

    function draw() {
        frame++;
        ctx.setTransform(1, 0, 0, 1, 0, 0);
        const distanceX = canvas.width / 80;
        const growth = canvas.width / 1000;
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#fff';
        for (const c of circles) {
            ctx.beginPath();
            if (frame < 65) {
                c.x -= distanceX;
                c.size += growth;
            } else if (frame < 500) {
                c.x -= distanceX * 0.02;
                c.size += growth * 0.2;
            }
            ctx.arc(c.x, c.y, c.size, 0, Math.PI * 2);
            ctx.fill();
        }
        if (frame > 500) return; // final state reached: page is white, stop the loop
        rafId = requestAnimationFrame(draw);
    }

    function start() {
        cancelAnimationFrame(rafId);
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        frame = 0;
        initCircles();
        draw();
        runCharacters();
    }

    let resizeTimer;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(start, 200);
    });
    start();
})();
