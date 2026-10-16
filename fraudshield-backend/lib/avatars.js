// lib/avatars.js — profile pictures live in the database (table `avatars`), not on
// disk, so they survive restarts on hosts without a persistent disk. URLs keep the
// historical shape /uploads/avatars/u<id>-<random>.<ext>; the name is server-chosen.

const NAME = /^u\d+-[\w-]+\.(png|jpg|webp|gif)$/;
const URL_PREFIX = '/uploads/avatars/';
const MIME = { png: 'image/png', jpg: 'image/jpeg', webp: 'image/webp', gif: 'image/gif' };

const isAvatarName = name => typeof name === 'string' && NAME.test(name);
const nameFromUrl = url => {
    const name = typeof url === 'string' && url.startsWith(URL_PREFIX) ? url.slice(URL_PREFIX.length) : '';
    return isAvatarName(name) ? name : null;
};
const mimeFor = name => MIME[NAME.exec(name)[1]];

module.exports = { URL_PREFIX, isAvatarName, nameFromUrl, mimeFor };
