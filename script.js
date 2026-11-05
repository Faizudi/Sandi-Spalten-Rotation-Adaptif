/* ==========================================================================
   KONSTANTA
   ========================================================================== */
const ROWS = 2;                    // jumlah baris matriks
const COLS = 5;                    // jumlah kolom matriks
const BLOCK_SIZE = ROWS * COLS;    // 10 karakter per blok
const PAD_CHAR = 'X';              // karakter padding

/* ==========================================================================
   PERSIAPAN KUNCI
   ========================================================================== */

/**
 * Menghitung informasi kunci:
 *  - totalAscii  : jumlah nilai ASCII seluruh huruf kunci
 *  - rankByCol   : peringkat alfabetis (1..5) untuk setiap posisi kolom
 *  - baseOrder   : Urutan Dasar Kolom (indeks kolom 0..4, diurutkan menurut peringkat 1..5)
 *
 * Contoh KUNCI:
 *   K U N C I  -> ASCII 75+85+78+67+73 = 378
 *   peringkat  -> K=3, U=5, N=4, C=1, I=2   (rankByCol = [3,5,4,1,2])
 *   peringkat 1 ada di kolom ke-4, peringkat 2 di kolom ke-5, dst.
 *   => Urutan Dasar Kolom (1-based) = [4,5,1,3,2]; (0-based) = [3,4,0,2,1]
 */
function calculateKeyInfo(rawKey) {
  const key = String(rawKey).toUpperCase().replace(/\s+/g, '');
  if (!/^[A-Z]{5}$/.test(key)) {
    throw new Error('Kata kunci harus terdiri dari tepat 5 huruf (A-Z).');
  }

  // Total nilai ASCII seluruh karakter kunci
  let totalAscii = 0;
  for (const ch of key) totalAscii += ch.charCodeAt(0);

  // Urutkan indeks kolom menurut huruf; jika huruf kembar, posisi lebih kiri didahulukan
  const baseOrder = [...key.split('').keys()].sort((a, b) => {
    if (key[a] !== key[b]) return key[a] < key[b] ? -1 : 1;
    return a - b;
  });

  // rankByCol[kolom] = peringkat (1..5) huruf pada kolom tersebut
  const rankByCol = new Array(COLS);
  baseOrder.forEach((col, i) => { rankByCol[col] = i + 1; });

  return { key, totalAscii, rankByCol, baseOrder };
}

/**
 * Rencana per blok (dipakai bersama oleh enkripsi dan dekripsi agar selalu konsisten).
 *
 *  shift     = (TotalASCII + b) mod 5
 *  order     = baseOrder digeser KIRI sebanyak `shift` langkah (rotasi melingkar)
 *              order[i] = baseOrder[(i + shift) mod 5]
 *  startRows = untuk tiap kolom pada `order`, baris awal baca = (peringkat_kolom + b) mod 2
 */
function getBlockPlan(info, b) {
  const shift = (info.totalAscii + b) % COLS;

  // Rotasi kiri: elemen ke-i hasil = elemen ke-(i+shift) dari urutan dasar (melingkar)
  const order = info.baseOrder.map((_, i) => info.baseOrder[(i + shift) % COLS]);

  // Baris awal baca untuk setiap kolom (mengikuti urutan baca `order`)
  const startRows = order.map(col => (info.rankByCol[col] + b) % ROWS);

  return { shift, order, startRows };
}

/* ==========================================================================
   ENKRIPSI
   ========================================================================== */

/**
 * Enkripsi TKRA.
 * Mengembalikan { result, log } (log berupa array string).
 */
function encryptTKRA(plaintext, rawKey) {
  const log = [];
  const info = calculateKeyInfo(rawKey);

  log.push('=== ENKRIPSI ===');
  log.push(`Kunci          : ${info.key}`);
  log.push(`Total ASCII    : ${info.totalAscii}`);
  log.push(`Peringkat kunci: [${info.rankByCol.join(', ')}]`);
  log.push(`Urutan dasar   : [${info.baseOrder.map(c => c + 1).join(', ')}] (kolom 1-based)`);

  // 1) Normalisasi: huruf kapital + hapus semua spasi/whitespace
  let text = String(plaintext).toUpperCase().replace(/\s+/g, '');
  if (text.length === 0) throw new Error('Teks tidak boleh kosong.');
  log.push(`Teks normal    : ${text} (${text.length} karakter)`);

  // 2) Padding 'X' agar panjang kelipatan 10
  const padCount = (BLOCK_SIZE - (text.length % BLOCK_SIZE)) % BLOCK_SIZE;
  text += PAD_CHAR.repeat(padCount);
  if (padCount > 0) log.push(`Padding        : +${padCount} huruf '${PAD_CHAR}' -> ${text}`);

  let cipher = '';
  const blockCount = text.length / BLOCK_SIZE;

  for (let b = 0; b < blockCount; b++) {
    const block = text.substr(b * BLOCK_SIZE, BLOCK_SIZE);

    // 3) Isi matriks 2 x 5 secara horizontal (baris demi baris)
    const matrix = [];
    for (let r = 0; r < ROWS; r++) {
      matrix.push(block.substr(r * COLS, COLS).split(''));
    }

    const { shift, order, startRows } = getBlockPlan(info, b);

    log.push('');
    log.push(`--- Blok ${b} : ${block} ---`);
    log.push(`Matriks  Baris 0: ${matrix[0].join(' ')}`);
    log.push(`         Baris 1: ${matrix[1].join(' ')}`);
    log.push(`shift = (${info.totalAscii} + ${b}) mod 5 = ${shift}`);
    log.push(`Urutan kolom setelah geser kiri ${shift}x: [${order.map(c => c + 1).join(', ')}]`);

    // 4) Baca tiap kolom sesuai urutan hasil rotasi.
    //    Mulai dari baris startRow, lalu lanjut melingkar ke bawah:
    //    (startRow + k) mod 2 untuk k = 0..1
    let blockCipher = '';
    order.forEach((col, i) => {
      const startRow = startRows[i];
      let chunk = '';
      for (let k = 0; k < ROWS; k++) {
        const row = (startRow + k) % ROWS;   // pembacaan melingkar
        chunk += matrix[row][col];
      }
      blockCipher += chunk;
      log.push(`Kolom ${col + 1} (peringkat ${info.rankByCol[col]}) mulai baris ${startRow} -> ${chunk}`);
    });

    log.push(`Cipher blok ${b}: ${blockCipher}`);
    cipher += blockCipher;
  }

  log.push('');
  log.push(`Ciphertext akhir: ${cipher}`);
  return { result: cipher, log };
}

/* ==========================================================================
   DEKRIPSI
   ========================================================================== */

/**
 * Dekripsi TKRA.
 * Mengembalikan { result, log }.
 */
function decryptTKRA(ciphertext, rawKey) {
  const log = [];
  const info = calculateKeyInfo(rawKey);

  log.push('=== DEKRIPSI ===');
  log.push(`Kunci          : ${info.key}`);
  log.push(`Total ASCII    : ${info.totalAscii}`);
  log.push(`Peringkat kunci: [${info.rankByCol.join(', ')}]`);
  log.push(`Urutan dasar   : [${info.baseOrder.map(c => c + 1).join(', ')}] (kolom 1-based)`);

  const text = String(ciphertext).toUpperCase().replace(/\s+/g, '');
  if (text.length === 0) throw new Error('Teks tidak boleh kosong.');
  if (text.length % BLOCK_SIZE !== 0) {
    throw new Error(`Panjang ciphertext (${text.length}) harus kelipatan ${BLOCK_SIZE} karakter.`);
  }
  log.push(`Ciphertext     : ${text} (${text.length} karakter)`);

  let plain = '';
  const blockCount = text.length / BLOCK_SIZE;

  for (let b = 0; b < blockCount; b++) {
    const block = text.substr(b * BLOCK_SIZE, BLOCK_SIZE);

    // Hitung ulang shift, urutan kolom, dan baris awal baca (identik dengan enkripsi)
    const { shift, order, startRows } = getBlockPlan(info, b);

    log.push('');
    log.push(`--- Blok ${b} : ${block} ---`);
    log.push(`shift = (${info.totalAscii} + ${b}) mod 5 = ${shift}`);
    log.push(`Urutan kolom setelah geser kiri ${shift}x: [${order.map(c => c + 1).join(', ')}]`);

    // Matriks kosong 2 x 5
    const matrix = Array.from({ length: ROWS }, () => new Array(COLS).fill(''));

    // Setiap kolom pada `order` menyumbang 2 karakter ciphertext berurutan.
    // Karakter ke-k dari kolom tersebut berasal dari baris (startRow + k) mod 2.
    order.forEach((col, i) => {
      const startRow = startRows[i];
      const chunk = block.substr(i * ROWS, ROWS);
      for (let k = 0; k < ROWS; k++) {
        const row = (startRow + k) % ROWS;   // balikan dari pembacaan melingkar
        matrix[row][col] = chunk[k];
      }
      log.push(`Kolom ${col + 1} (peringkat ${info.rankByCol[col]}) mulai baris ${startRow} <- ${chunk}`);
    });

    log.push(`Matriks  Baris 0: ${matrix[0].join(' ')}`);
    log.push(`         Baris 1: ${matrix[1].join(' ')}`);

    // Baca horizontal: Baris 0 lalu Baris 1
    const blockPlain = matrix[0].join('') + matrix[1].join('');
    log.push(`Plain blok ${b}: ${blockPlain}`);
    plain += blockPlain;
  }

  // Bersihkan padding 'X' di akhir teks
  const trimmed = plain.replace(new RegExp(PAD_CHAR + '+$'), '');
  const removed = plain.length - trimmed.length;
  log.push('');
  log.push(`Padding dihapus: ${removed} karakter '${PAD_CHAR}'`);
  log.push(`Plaintext akhir: ${trimmed}`);
  log.push('Catatan: huruf spasi tidak dapat dipulihkan, dan huruf X asli di akhir teks ikut terhapus.');

  return { result: trimmed, log };
}

/* ==========================================================================
   ANTARMUKA
   ========================================================================== */
const elInput  = document.getElementById('inputText');
const elKey    = document.getElementById('secretKey');
const elOutput = document.getElementById('output');
const elLog    = document.getElementById('log');

// Menjalankan fungsi proses dan menampilkan hasil / error
function run(fn) {
  try {
    const { result, log } = fn(elInput.value, elKey.value);
    elOutput.classList.remove('error');
    elOutput.textContent = result === '' ? '(kosong)' : result;
    elLog.textContent = log.join('\n');
  } catch (err) {
    elOutput.classList.add('error');
    elOutput.textContent = err.message;
    elLog.textContent = 'Terjadi kesalahan: ' + err.message;
  }
}

document.getElementById('btnEncrypt').addEventListener('click', () => run(encryptTKRA));
document.getElementById('btnDecrypt').addEventListener('click', () => run(decryptTKRA));

document.getElementById('btnCopy').addEventListener('click', async (e) => {
  const btn = e.currentTarget;
  const text = elOutput.textContent;
  if (!text || text === '-' || elOutput.classList.contains('error')) return;
  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = 'Tersalin!';
  } catch (_) {
    btn.textContent = 'Gagal';
  }
  setTimeout(() => { btn.textContent = 'Salin'; }, 1500);
});

