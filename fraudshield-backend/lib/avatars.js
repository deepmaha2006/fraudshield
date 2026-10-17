// lib/avatars.js — profile pictures live in the database (table `avatars`), not on
// disk, so they survive restarts on hosts without a persistent disk.

// Accepts only fully-random 22-char base64url names (<random>.<ext>).
// Run scripts/migrate-avatar-names.js before deploying so legacy u<id>-* rows are renamed.
const NAME = /^[A-Za-z0-9_-]{22}\.(png|jpg|webp|gif)$/;
const URL_PREFIX = '/uploads/avatars/';
const MIME = { png: 'image/png', jpg: 'image/jpeg', webp: 'image/webp', gif: 'image/gif' };

const isAvatarName = name => typeof name === 'string' && NAME.test(name);
const nameFromUrl = url => {
    const name = typeof url === 'string' && url.startsWith(URL_PREFIX) ? url.slice(URL_PREFIX.length) : '';
    return isAvatarName(name) ? name : null;
};
const mimeFor = name => MIME[NAME.exec(name)[1]];

module.exports = { URL_PREFIX, isAvatarName, nameFromUrl, mimeFor };
