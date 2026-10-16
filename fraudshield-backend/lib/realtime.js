// lib/realtime.js — Server-Sent Events hub. Each signed-in console tab holds
// one stream; detections and integration status changes are pushed instantly.

const clients = new Map(); // userId -> Set<res>
const MAX_STREAMS_PER_USER = 10; // bounds open sockets per account

function subscribe(userId, res) {
    const existing = clients.get(userId);
    if (existing && existing.size >= MAX_STREAMS_PER_USER) {
        // Close the oldest stream rather than refusing: a reloaded tab must always get a feed.
        const oldest = existing.values().next().value;
        existing.delete(oldest);
        oldest.end();
    }
    res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache, no-transform',
        Connection: 'keep-alive',
        'X-Accel-Buffering': 'no',
    });
    res.write('retry: 4000\n\n');
    if (!clients.has(userId)) clients.set(userId, new Set());
    clients.get(userId).add(res);

    const heartbeat = setInterval(() => res.write(`: hb ${Date.now()}\n\n`), 25000);
    res.on('close', () => {
        clearInterval(heartbeat);
        clients.get(userId)?.delete(res);
    });
    publish(userId, 'hello', { at: new Date().toISOString() });
}

function publish(userId, event, data) {
    const set = clients.get(userId);
    if (!set) return;
    const frame = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const res of set) res.write(frame);
}

const listenerCount = userId => clients.get(userId)?.size || 0;

module.exports = { subscribe, publish, listenerCount };
