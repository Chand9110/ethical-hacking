import { db } from '../db.ts';
import { DEMO_STORE_BASE_URL } from '../security/urlValidator.ts';

export type DemoPosture = 'vulnerable' | 'hardened';

export interface VirtualHttpResponse {
  finalUrl: string;
  status: number;
  headers: Record<string, string>;
  setCookies: string[];
  body: string;
  responseTimeMs: number;
}

export function getDemoStorePosture(): DemoPosture {
  const row = db.prepare(`SELECT posture FROM Demo_Store_Config WHERE id = 1`).get() as
    | { posture: DemoPosture }
    | undefined;
  return row?.posture === 'hardened' ? 'hardened' : 'vulnerable';
}

export function setDemoStorePosture(posture: DemoPosture): void {
  db.prepare(`UPDATE Demo_Store_Config SET posture = ?, updated_at = datetime('now') WHERE id = 1`).run(posture);
}

function escapeHtml(text: string): string {
  return text
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

export function fetchDemoStorePage(rawUrl: string): VirtualHttpResponse {
  const posture = getDemoStorePosture();
  const parsed = new URL(rawUrl);
  const pathname = parsed.pathname || '/';
  const isHardened = posture === 'hardened';

  const baseHeaders: Record<string, string> = isHardened
    ? {
        'content-type': 'text/html; charset=utf-8',
        'content-security-policy': "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';",
        'strict-transport-security': 'max-age=31536000; includeSubDomains',
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'strict-origin-when-cross-origin',
        'permissions-policy': 'geolocation=(), microphone=(), camera=()',
      }
    : {
        'content-type': 'text/html; charset=utf-8',
        server: 'Apache/2.4.49 (Unix)',
        'x-powered-by': 'PHP/7.4.3',
      };

  const setCookies = isHardened
    ? ['meridian_sid=demo_hardened_token_92f8; Path=/; HttpOnly; Secure; SameSite=Strict']
    : ['meridian_sid=demo_baseline_token_10a4; Path=/'];

  const csrfInput = isHardened
    ? '<input type="hidden" name="_csrf" value="aegis_demo_csrf_91d2b3c4" />'
    : '';

  const navHtml = `
    <nav>
      <a href="${DEMO_STORE_BASE_URL}/">Home</a>
      <a href="${DEMO_STORE_BASE_URL}/products">Catalog</a>
      <a href="${DEMO_STORE_BASE_URL}/product?id=101">Featured Watch</a>
      <a href="${DEMO_STORE_BASE_URL}/search?q=watch">Search</a>
      <a href="${DEMO_STORE_BASE_URL}/cart">Cart</a>
      <a href="${DEMO_STORE_BASE_URL}/checkout">Checkout</a>
      <a href="${DEMO_STORE_BASE_URL}/login">Sign In</a>
    </nav>
  `;

  if (pathname === '/' || pathname === '') {
    return {
      finalUrl: `${DEMO_STORE_BASE_URL}/`,
      status: 200,
      headers: baseHeaders,
      setCookies,
      responseTimeMs: 28,
      body: `<!doctype html>
<html><head><title>Meridian Mart — Demo E-Commerce Store</title></head>
<body>
  <header><h1>Meridian Mart Online Store</h1>${navHtml}</header>
  <main>
    <form method="GET" action="/search">
      <input type="text" name="q" placeholder="Search products..." />
      <button type="submit">Search</button>
    </form>
    <section>
      <article><a href="/product?id=101">Chronograph Field Watch — $249.00</a></article>
      <article><a href="/product?id=102">Minimalist Leather Satchel — $189.00</a></article>
    </section>
  </main>
</body></html>`,
    };
  }

  if (pathname === '/products') {
    return {
      finalUrl: `${DEMO_STORE_BASE_URL}/products`,
      status: 200,
      headers: baseHeaders,
      setCookies: [],
      responseTimeMs: 31,
      body: `<!doctype html>
<html><head><title>Catalog — Meridian Mart</title></head>
<body>
  <header>${navHtml}</header>
  <main>
    <h1>Product Catalog</h1>
    <ul>
      <li><a href="/product?id=101">Chronograph Field Watch ($249)</a></li>
      <li><a href="/product?id=102">Minimalist Leather Satchel ($189)</a></li>
      <li><a href="/product?id=103">Ceramic Pour-Over Set ($74)</a></li>
    </ul>
  </main>
</body></html>`,
    };
  }

  if (pathname === '/product') {
    const idParam = parsed.searchParams.get('id') ?? '101';
    if (!isHardened && /['";]/.test(idParam)) {
      return {
        finalUrl: parsed.toString(),
        status: 500,
        headers: baseHeaders,
        setCookies: [],
        responseTimeMs: 44,
        body: `<!doctype html>
<html><head><title>500 Database Error — Meridian Mart</title></head>
<body>
  <h1>Application Error</h1>
  <pre>SQLITE_ERROR: near "'": syntax error in query: SELECT id, title, price FROM products WHERE id = '${idParam}'</pre>
</body></html>`,
      };
    }

    const safeId = /^\d+$/.test(idParam) ? idParam : '101';
    return {
      finalUrl: parsed.toString(),
      status: 200,
      headers: baseHeaders,
      setCookies: [],
      responseTimeMs: 34,
      body: `<!doctype html>
<html><head><title>Product #${escapeHtml(safeId)} — Meridian Mart</title></head>
<body>
  <header>${navHtml}</header>
  <main>
    <h1>Chronograph Field Watch (#${escapeHtml(safeId)})</h1>
    <p>Price: $249.00</p>
    <form method="POST" action="/cart">
      ${csrfInput}
      <input type="hidden" name="product_id" value="${escapeHtml(safeId)}" />
      <input type="number" name="quantity" value="1" min="1" max="10" />
      <button type="submit">Add to Cart</button>
    </form>
  </main>
</body></html>`,
    };
  }

  if (pathname === '/search') {
    const query = parsed.searchParams.get('q') ?? '';
    const renderedQuery = isHardened ? escapeHtml(query) : query;
    return {
      finalUrl: parsed.toString(),
      status: 200,
      headers: baseHeaders,
      setCookies: [],
      responseTimeMs: 29,
      body: `<!doctype html>
<html><head><title>Search — Meridian Mart</title></head>
<body>
  <header>${navHtml}</header>
  <main>
    <form method="GET" action="/search">
      <input type="text" name="q" value="${escapeHtml(query)}" />
      <button type="submit">Search</button>
    </form>
    <h2>Search Results for: ${renderedQuery}</h2>
    <p>Showing matching items from Meridian Mart catalog.</p>
  </main>
</body></html>`,
    };
  }

  if (pathname === '/cart') {
    return {
      finalUrl: `${DEMO_STORE_BASE_URL}/cart`,
      status: 200,
      headers: baseHeaders,
      setCookies: [],
      responseTimeMs: 25,
      body: `<!doctype html>
<html><head><title>Shopping Cart — Meridian Mart</title></head>
<body>
  <header>${navHtml}</header>
  <main>
    <h1>Your Shopping Cart</h1>
    <form method="POST" action="/cart">
      ${csrfInput}
      <input type="number" name="qty_101" value="1" />
      <button type="submit">Update Cart</button>
    </form>
    <a href="/checkout">Proceed to Checkout</a>
  </main>
</body></html>`,
    };
  }

  if (pathname === '/checkout') {
    const actionTarget = isHardened ? '/checkout' : 'http://demo-store.aegiscommerce.test/checkout';
    const cardAutoComplete = isHardened ? 'autocomplete="off"' : 'autocomplete="on"';
    return {
      finalUrl: `${DEMO_STORE_BASE_URL}/checkout`,
      status: 200,
      headers: baseHeaders,
      setCookies: [],
      responseTimeMs: 39,
      body: `<!doctype html>
<html><head><title>Checkout — Meridian Mart</title></head>
<body>
  <header>${navHtml}</header>
  <main>
    <h1>Secure Checkout</h1>
    <form method="POST" action="${actionTarget}">
      ${csrfInput}
      <input type="text" name="full_name" placeholder="Full Name" />
      <input type="email" name="email" placeholder="Email Address" />
      <input type="text" name="shipping_address" placeholder="Shipping Address" />
      <input type="text" name="card_number" placeholder="Card Number" ${cardAutoComplete} />
      <input type="password" name="cvv" placeholder="Security Code" ${cardAutoComplete} />
      <button type="submit">Place Order</button>
    </form>
  </main>
</body></html>`,
    };
  }

  if (pathname === '/login') {
    const pwdAuto = isHardened ? 'autocomplete="current-password"' : 'autocomplete="on"';
    return {
      finalUrl: `${DEMO_STORE_BASE_URL}/login`,
      status: 200,
      headers: baseHeaders,
      setCookies: [],
      responseTimeMs: 22,
      body: `<!doctype html>
<html><head><title>Customer Sign In — Meridian Mart</title></head>
<body>
  <header>${navHtml}</header>
  <main>
    <h1>Customer Sign In</h1>
    <form method="POST" action="/login">
      ${csrfInput}
      <input type="email" name="email" placeholder="Email" />
      <input type="password" name="password" placeholder="Password" ${pwdAuto} />
      <button type="submit">Sign In</button>
    </form>
  </main>
</body></html>`,
    };
  }

  // Sensitive paths check (.env / .git / robots.txt)
  if (pathname === '/.env') {
    if (isHardened) {
      return {
        finalUrl: parsed.toString(),
        status: 404,
        headers: baseHeaders,
        setCookies: [],
        responseTimeMs: 12,
        body: 'Not Found',
      };
    }
    return {
      finalUrl: parsed.toString(),
      status: 200,
      headers: { ...baseHeaders, 'content-type': 'text/plain' },
      setCookies: [],
      responseTimeMs: 14,
      body: '# Simulated exposed config artifact (non-secret demo placeholder)\nAPP_ENV=staging\nDEBUG=true\nDB_CONNECTION=sqlite',
    };
  }

  return {
    finalUrl: parsed.toString(),
    status: 404,
    headers: baseHeaders,
    setCookies: [],
    responseTimeMs: 15,
    body: '<!doctype html><html><body><h1>404 Page Not Found</h1></body></html>',
  };
}
