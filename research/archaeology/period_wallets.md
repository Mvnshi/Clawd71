# Period-appropriate (2013-2015) Bitcoin key-generation implementations

Scope: candidate deterministic-wallet / key-generation implementations an amateur
puzzle creator plausibly used or adapted circa Jan 2015 (the puzzle transaction's
block-339085 creation date) to produce "consecutive keys from a deterministic
wallet (masked with leading 000...0001 to set difficulty)" per the creator's
widely-quoted (not yet primary-sourced by me -- see Finding 6) statement.

For each candidate: precise algorithm (so it is directly implementable),
historical currency in 2013-2015, and an explicit verdict on whether it is
already covered by the seq_counter/lcg/xorshift_mt/hash_chain/timestamp_creation
hypothesis buckets or represents a distinct, testable mechanism.

---

## Finding 1 -- Electrum 1.x ("old-style") deterministic wallet -- CONCRETE, TESTABLE, NOT fully covered by existing buckets

Electrum's pre-BIP32 scheme (live 2011-2013, still widely installed/referenced
through 2015; code preserved to this day in `spesmilo/electrum` as
`old_mnemonic.py` / the `old_mnemonic` code path, and independently reproduced in
third-party recovery tools). Exact algorithm, confirmed from source
(`Evil-Knievel/electrum-cracker/bruteforcer.py`, a faithful reimplementation of
Electrum's `wallet.py`/`old.py` for cracking purposes):

```python
def stretch_key(seed):
    oldseed = seed
    for i in range(100000):
        seed = hashlib.sha256(seed + oldseed).digest()
    return string_to_number(seed)          # -> secexp

def mpk_from_seed(seed):
    secexp = stretch_key(seed)
    master_private_key = ecdsa.SigningKey.from_secret_exponent(secexp, curve=SECP256k1)
    return master_private_key.get_verifying_key().to_string()   # -> mpk (64 bytes, x||y)

def get_sequence(mpk, n, for_change):
    # Hash() in this codebase (and in pywallet.py / bitcointools, the common
    # ancestor utility libraries of the era) is double-SHA256:
    #   Hash(x) = sha256(sha256(x).digest()).digest()
    return string_to_number(Hash(("%d:%d:" % (n, for_change)).encode() + mpk))

def child_privkey(secexp, mpk, n, for_change=0):
    z = get_sequence(mpk, n, for_change)
    return (secexp + z) % CURVE_ORDER      # secp256k1 group order
```

So the i-th "receiving address" private key in an Electrum 1.x wallet is
`(secexp + H("i:0:" + mpk)) mod n`, an **additive** (mod curve order) hash
chain keyed by the plaintext sequence index `i` and the wallet's own master
public key -- not a simple `H(seed||i)` truncation. If the puzzle creator ran
`n=1..70` (or `n=0..69`) down the receiving-address chain of one Electrum 1.x
wallet and then, for puzzle `k`, took the low `k-1` bits of `child_privkey(k)`
and forced the top bit to 1, that reproduces the creator's own description
("consecutive keys from a deterministic wallet, masked with leading zeros").

**Testability**: fully implementable today (the code above is complete and
runnable with `ecdsa`+`hashlib`). It is NOT brute-forceable over `secexp`
(256-bit secret), but IS testable in two useful ways sibling agents can run
directly against `solved_puzzles.json`:
  (a) *seed dictionary attack* -- enumerate plausible low-entropy Electrum
      12-word seed phrases or 2013-era Electrum seed-generation outputs
      (short guessable phrases, sequential/all-zero test seeds, common
      Bitcointalk-era example seeds) through `stretch_key` -> `secexp`/`mpk`
      -> `child_privkey(k)` masked to `k` bits, and diff against all 70 known
      keys at once (any single seed that reproduces even 3-4 of the 70 keys
      simultaneously is astronomically significant and immediately falsifies
      or confirms the hypothesis -- this is a strong, cheap test).
  (b) *structural signature* -- even without recovering `secexp`, this scheme
      predicts that `key_(n+1) - key_n` (mod 2^min(n,n+1) bits, after
      correcting for the mask/truncation) should NOT behave like a fixed-step
      arithmetic or LCG recurrence (ruling it in/out relative to seq_counter/
      lcg hypotheses specifically), because the increment is
      `H(n+1:...)-H(n:...)` mod curve order -- cryptographically unpredictable
      even if the scheme is correct. In other words: if this hypothesis is
      right, NO amount of statistical analysis of the 70 known keys alone
      will ever detect it (that is what makes it a *bona fide* deterministic
      wallet, as opposed to a weak PRNG) -- only a seed/passphrase dictionary
      attack under (a) can find it. This is worth stating plainly per the
      anti-bullshit rule: this hypothesis, if true, is not exploitable by
      pattern-mining, only by guessing the seed.

**Verdict**: distinct from generic `hash_chain` in the ledger because of the
specific `"%d:%d:" % (n, for_change) + mpk` preimage format and **modular
addition** (not XOR/truncation) recombination step -- worth encoding exactly
this way if the Hypotheses phase wants to claim it tested "Electrum" rather
than a generic hash chain. Recommend folding into the `hash_chain` bucket as a
parameterized variant (`hash_chain_electrum1`) rather than a wholly new
bucket, but implement the exact preimage format above, not a generic one.

Source: `spesmilo/electrum` (`old_mnemonic.py`, current repo still carries
the legacy module name); reconstruction verified against
`Evil-Knievel/electrum-cracker/bruteforcer.py` (a from-scratch Python
reimplementation of the same algorithm for wallet-cracking, cross-checked
against the Electrum 1.x `wallet.py`/`old.py` source it targets).

---

## Finding 2 -- "Type-1" deterministic wallet (Mike Caldwell, 2011) -- CONCRETE, TESTABLE, simplest candidate

Documented on the Bitcoin Wiki's "Deterministic wallet" page as the original,
pre-BIP32 scheme that predates Electrum's and Armory's more elaborate designs;
still commonly referenced/re-implemented in 2013-2015 hobbyist scripts because
of its trivial simplicity (no MPK, no EC math beyond the final privkey->pubkey
step):

```
key_n = SHA256(masterstring + str(n))     # n = 1, 2, 3, ... (ASCII decimal, no padding)
```

**Testability**: this is the cheapest, most directly brute-forceable
hypothesis in the whole archaeology set. Sibling Hypotheses-phase agents can
enumerate a wordlist of plausible `masterstring` values (empty string,
"bitcoin", "satoshi", "puzzle", the address/puzzle creator's likely
Bitcointalk-era phrases, digits-of-pi-style strings, etc.) crossed with both
`n` and `n-1` starting conventions and immediately mask each
`SHA256(masterstring+str(n))` to `n` bits (force top bit) and diff against all
70 known keys. A true positive here is unambiguous (see anti-bullshit
Monte-Carlo framing below) because it must match *many* of the 70 keys at
once for a fixed `masterstring`, not just one.

**Null-model framing for the Hypotheses phase**: for a WRONG `masterstring`,
the probability that `SHA256(masterstring+str(n)) mod 2^(n-1)` matches the
true `lower_bits_hex` of puzzle `n` by chance is `~2^-(n-1)`, i.e.
astronomically small for any `n>20`; so this hypothesis is either
spectacularly confirmed on the first few dozen candidate strings, or it should
be dropped outright rather than "graded" -- there is no meaningful partial
credit / near-miss statistic worth Monte-Carlo testing here (a single correct
low-bit match on puzzle #40+ under this scheme is already a p<1e-12 event).
This makes it a cheap, high-value, unambiguous first test to run before
investing in the fuzzier statistical hypotheses.

**Verdict**: essentially a specific, well-documented instance of the
`hash_chain` bucket (`H(seed||n)`, no stretching) -- but concrete and cheap
enough that it is worth running as its own dictionary-attack pass rather than
lumped into generic statistical hash_chain testing.

Source: Bitcoin Wiki, "Deterministic wallet" article, "Type-1: Single chain of
private keys" section (attributed to Mike Caldwell / "the Casascius Type-1
scheme"); cross-referenced against Greg Maxwell's June 2011 critique/rebuttal
thread (which improved on it into what became BIP32) -- both period-correct
antecedents to Electrum/Armory.

---

## Finding 3 -- brainwallet.org / bitaddress.org "Brain Wallet" tab -- CONFIRMED algorithm, LOW relevance to *sequential* structure

Directly inspected the still-canonical open-source implementation
(`pointbiz/bitaddress.org`, the exact code that was `bitaddress.org` in
2013-2015 and was the single most commonly Bitcointalk-pasted client-side
generator of the era). The Brain Wallet tab's `view()` handler:

```javascript
var bytes = Crypto.SHA256(key, { asBytes: true });   // key = user passphrase, no salt
var btcKey = new Bitcoin.ECKey(bytes);                // raw 32 bytes used directly as secexp
```

i.e. `privkey = SHA256(passphrase)`, a single unsalted, unstretched hash --
exactly the widely-reported "brainwallet.org-style" scheme the task asked to
check, confirmed byte-for-byte from source rather than secondhand description.

**Relevance to the puzzle's sequential structure**: LOW as a standalone
mechanism, because a single `SHA256(passphrase)` produces one key, not a
sequence of 70+. It only becomes a *sequence* generator if combined with an
incrementing suffix/prefix per key -- which is precisely Finding 2 (Type-1)
above. Recommend treating "brainwallet-style" and "Type-1 deterministic
wallet" as the same testable hypothesis in the ledger (Finding 2 already
covers the exact formula); do not open a separate bucket for "brainwallet.org"
alone.

---

## Finding 4 -- bitaddress.org "Bulk Wallet" tab -- RULED OUT (negative finding, worth recording so sibling agents don't re-investigate)

Also directly inspected: this is the feature most superficially resembling
"generate a numbered sequence of keys for a puzzle/challenge," since its own
UI literally has a `Start index` field and outputs `Index,Address,PrivateKey`
CSV rows. However the actual generator code (`ninja.wallets.bulkwallet.batchCSV`,
`bitaddress.org.html` current source, structurally unchanged since the
2013-2015 era per the project's CHANGELOG):

```javascript
var key = new Bitcoin.ECKey(false);   // false => pull fresh randomness from the
                                       // page-global ARC4/window.crypto entropy pool
key.setCompressed(bulk.compressedAddrs);
bulk.csv.push((bulk.csvRowLimit - bulk.csvRowsRemaining + bulk.csvStartIndex) + "," + ...);
```

The `index` column is purely a CSV row label computed from `csvRowLimit`/
`csvRowsRemaining`/`csvStartIndex` -- it is **never fed into the key
generator**. Each row's private key is an independent draw from
bitaddress.org's shared browser-entropy RNG pool (the same ARC4 pool used by
the "Single Wallet" tab), not a function of the row index. This tool therefore
**cannot** produce the kind of index-keyed deterministic sequence the puzzle
exhibits, and should be excluded from further consideration as the puzzle's
generator. (It remains theoretically possible the creator scripted something
bitaddress.org-*like* but custom -- but the actual, widely-pasted
bitaddress.org tool itself is not a candidate.)

---

## Finding 5 -- Armory ("BitcoinArmory") Type-2 deterministic wallet -- PARTIALLY CONFIRMED, formula not fully pinned down from public web sources at this pass

Armory (etotheipi, first released 2011, actively used/discussed on
Bitcointalk through 2013-2015) implemented what the Bitcoin Wiki calls a
"Type-2" deterministic wallet: a root private key plus a single "chain code,"
with each subsequent key in the chain derived from the previous one by
elliptic-curve scalar multiplication against a value derived from hashing the
chain code together with the previous public/private key (i.e. a
**multiplicative** recurrence, structurally different from Electrum's
**additive** recurrence in Finding 1). One secondary source (a Medium
writeup, `kyodo-tech`, blocked by 403 on direct fetch but partially visible
via search-index snippet) states the per-step multiplier as
`k = SHA256(SHA256(pubkey)) XOR chaincode`, with
`pubkey_(i+1) = EC_multiply(pubkey_i, k)` (and correspondingly
`privkey_(i+1) = privkey_i * k mod N` on the private side). I was **not** able
to independently confirm this exact byte-level formula against Armory's own
source in this pass: the Python-visible layer of
`etotheipi/BitcoinArmory` (`armoryengine/ArmoryUtils.py`,
`armoryengine/PyBtcWallet.py`) delegates the actual EC chaining to a
SWIG-wrapped C++ module (`CppBlockUtils`) that I did not fetch/decompile.

**Recommendation for the Hypotheses phase**: before implementing an
"Armory-style" hypothesis, a sibling agent should pull the C++ source
(`cppForSwig/BtcWallet.cpp` / `EncryptionUtils.cpp` in
`etotheipi/BitcoinArmory`) to get the exact `k` formula and hash function
(the Wiki/Medium sources agree it's SHA256-based over pubkey+chaincode but
disagree/are vague on the exact byte layout and whether it's XOR or
concatenation into the hash). Until that is pinned down, do not report an
"Armory hypothesis" test result as either confirming or ruling out Armory --
only report tests against the concrete formula, once verified from primary
source. Flagging this as a genuinely distinct, **multiplicative** hash-chain
family (vs. Electrum's additive one and Type-1's memoryless one) that is NOT
equivalent to the existing `hash_chain`/`lcg` buckets and would need its own
bucket (`hash_chain_armory_mult`) once the exact formula is confirmed.

**Confidence this is even a plausible candidate**: LOW-MEDIUM. Armory in
2013-2015 was positioned as a "power user" cold-storage wallet requiring a
full local Bitcoin Core node and was less commonly used for casual
"paste a script, generate some keys" tasks than Electrum or brainwallet-style
one-liners; an amateur puzzle creator wanting a quick sequence of 70-256 keys
"for fun" seems more likely (Occam's razor, not evidence) to have reached for
Electrum's seed or a five-line Type-1-style SHA256 loop than to have driven
Armory's GUI/API for this purpose. Recorded for completeness per the task
brief, not because it is the leading candidate.

---

## Finding 6 -- Provenance of the creator's "no pattern... masked with leading 000...0001" quote

The task brief frames this quote as "widely-quoted, but independently
unverified by you until Archaeology phase." I was **not** able to trace it to
a specific, dated, first-person post by the puzzle's actual (still
anonymous) creator in this pass. What I confirmed:
  - The puzzle transaction itself was created ~15 Jan 2015 (block 339085),
    by an anonymous sender; the creator has never (as of this research) been
    identified.
  - The earliest Bitcointalk activity I could reach discussing the puzzle is
    topic 1306983 ("Bitcoin puzzle transaction ~32 BTC prize to who solves
    it"), opened by a user "Bulista" on **28 Dec 2015** -- eleven and a half
    months *after* the transaction -- explicitly describing themselves as
    someone who "stumbled upon" the transaction while running an unrelated
    brute-force bot, not as the creator. Bulista's own posts in that thread
    (as far as I could retrieve them) do not contain the "no pattern...
    masked with leading 000...0001" wording verbatim.
  - The quote as given appears verbatim across many secondary/tertiary
    sources (GitHub READMEs such as `roadhero/Bitcoin-Puzzle-Info`,
    `HomelessPhD/BTC32`, and puzzle-tracker sites), all of which present it
    as the creator's own words but without a directly cited, dated post URL
    that I could independently open and read in this pass (Bitcointalk's
    site structure/pagination and possible archival gaps limited what
    WebFetch could retrieve).
  - **Recommendation**: a subsequent archaeology/verification pass with
    direct Bitcointalk pagination access (or the Wayback Machine for
    `bitcointalk.org/index.php?topic=1306983.*` across many page numbers,
    since this is reportedly a multi-thousand-post thread) should locate and
    date-stamp the exact original post before this quote is treated as a
    confirmed primary source rather than a widely-repeated paraphrase. This
    matters because if the real quote differs even slightly (e.g. specifying
    *which* wallet software), that is directly actionable for Findings 1-2
    above.

---

## Summary table

| # | Candidate | Era-correct? | Formula confirmed from source? | Distinct from seq_counter/lcg/xorshift_mt/hash_chain/timestamp_creation? | Actionable test |
|---|---|---|---|---|---|
| 1 | Electrum 1.x old-seed wallet | Yes (2011-2013, still common 2015) | Yes, exact | Yes -- specific additive mod-N hash chain w/ mpk in preimage | Seed/passphrase dictionary attack; simultaneous multi-key match required |
| 2 | Type-1 deterministic wallet (Caldwell) | Yes (2011, simple enough to persist to 2015) | Yes, exact | Marginal -- a parameterized `hash_chain` instance, but cheap+decisive to test on its own | Masterstring dictionary attack across n=1..70 |
| 3 | brainwallet.org/bitaddress.org Brain Wallet | Yes (peak popularity 2013-2014) | Yes, exact (read from source) | No -- single-key only, folds into Finding 2 if sequenced | N/A standalone; see Finding 2 |
| 4 | bitaddress.org Bulk Wallet | Yes (tool existed) | Yes -- and disconfirmed | N/A -- ruled out, index not used in derivation | None needed; excluded |
| 5 | Armory Type-2 (root key + chain code) | Yes (2011-2015) | Partial -- concept yes, exact byte formula NOT pinned down | Yes, if confirmed -- multiplicative not additive | Needs C++ source pull before implementable |
| 6 | Primary source of creator's quote | N/A | Not located in this pass | N/A | Needs deeper Bitcointalk/Wayback pagination |
