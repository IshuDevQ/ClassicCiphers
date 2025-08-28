
import streamlit as st
import string
import math
import os
from collections import Counter
from io import StringIO
import pandas as pd

st.set_page_config(page_title="Classical Crypto Toolkit", layout="wide")

# ----- Alphabet & maps -----
ALPHABET = string.ascii_uppercase
A2I = {ch: i for i, ch in enumerate(ALPHABET)}
I2A = {i: ch for i, ch in enumerate(ALPHABET)}

def normalize(text: str) -> str:
    text = text.upper()
    out = ""
    for ch in text:
        if ch in ALPHABET:
            out += ch
    return out

# ----- Caesar -----
def caesar_encrypt(plain: str, k: int) -> str:
    p = normalize(plain)
    result = ""
    for ch in p:
        idx = A2I[ch]
        new_idx = (idx + k) % 26
        result += I2A[new_idx]
    return result

def caesar_decrypt(ct: str, k: int) -> str:
    c = normalize(ct)
    result = ""
    for ch in c:
        idx = A2I[ch]
        new_idx = (idx - k) % 26
        result += I2A[new_idx]
    return result



# ----- Affine -----
def egcd(a: int, b: int):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def inv_mod(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse for a modulo m")
    return x % m

def affine_encrypt(plain: str, a: int, b: int) -> str:
    if math.gcd(a, 26) != 1:
        raise ValueError("Parameter 'a' must be coprime with 26")
    p = normalize(plain)
    result = ""
    for ch in p:
        idx = A2I[ch]
        new_idx = (a * idx + b) % 26
        result += I2A[new_idx]
    return result

def affine_decrypt(ct: str, a: int, b: int) -> str:
    a_inv = inv_mod(a, 26)
    c = normalize(ct)
    result = ""
    for ch in c:
        idx = A2I[ch]
        new_idx = (a_inv * (idx - b)) % 26
        result += I2A[new_idx]
    return result

# ----- Vigenère -----
def vigenere_encrypt(plain: str, key: str) -> str:
    p = normalize(plain)
    k = normalize(key)
    if len(k) == 0:
        raise ValueError("Key must contain at least one A–Z letter")
    result = ""
    for i, ch in enumerate(p):
        key_ch = k[i % len(k)]
        new_idx = (A2I[ch] + A2I[key_ch]) % 26
        result += I2A[new_idx]
    return result

def vigenere_decrypt(ct: str, key: str) -> str:
    c = normalize(ct)
    k = normalize(key)
    if len(k) == 0:
        raise ValueError("Key must contain at least one A–Z letter")
    result = ""
    for i, ch in enumerate(c):
        key_ch = k[i % len(k)]
        new_idx = (A2I[ch] - A2I[key_ch]) % 26
        result += I2A[new_idx]
    return result

# ----- English frequencies & chi-square -----
EN_FREQ = {
    'E':12.70,'T':9.06,'A':8.17,'O':7.51,'I':6.97,'N':6.75,'S':6.33,'H':6.09,'R':5.99,'D':4.25,
    'L':4.03,'C':2.78,'U':2.76,'M':2.41,'W':2.36,'F':2.23,'G':2.02,'Y':1.97,'P':1.93,'B':1.49,
    'V':0.98,'K':0.77,'J':0.15,'X':0.15,'Q':0.10,'Z':0.07
}
for _k in list(EN_FREQ.keys()):
    EN_FREQ[_k] = EN_FREQ[_k] / 100.0

def chi_square_score(text: str) -> float:
    t = normalize(text)
    if len(t) == 0:
        return float('inf')
    N = len(t)
    counts = Counter(t)
    score = 0.0
    for ch in ALPHABET:
        O = counts.get(ch, 0)
        E = EN_FREQ[ch] * N
        if E == 0:
            E = 1e-9
        diff = O - E
        score += (diff * diff) / E
    return score

# ----- Caesar breaker -----
def break_caesar(ct: str):
    best_key = None
    best_pt = ""
    best_score = float("inf")
    for k in range(26):
        pt = caesar_decrypt(ct, k)
        s = chi_square_score(pt)
        if s < best_score:
            best_key = k
            best_pt = pt
            best_score = s
    return best_key, best_pt, best_score

# ----- Vigenère helpers (preserve case + dictionary attack) -----
DEFAULT_DICT_PATH = "dictionary.txt"
WORD_PERCENTAGE = 40
LETTER_PERCENTAGE = 85
MIN_KEY_LEN = 1
MAX_KEY_LEN = 32

def vigenere_decrypt_message_preserve_case(key: str, ciphertext: str) -> str:
    if not key:
        return ciphertext
    key_u = "".join([ch for ch in key.upper() if ch in ALPHABET])
    if len(key_u) == 0:
        return ciphertext
    pt_chars = []
    ki = 0
    for ch in ciphertext:
        ch_up = ch.upper()
        if ch_up in ALPHABET:
            k = ord(key_u[ki % len(key_u)]) - ord('A')
            c_idx = ord(ch_up) - ord('A')
            p_idx = (c_idx - k) % 26
            p_ch = chr(ord('A') + p_idx)
            if ch.islower():
                p_ch = p_ch.lower()
            pt_chars.append(p_ch)
            ki += 1
        else:
            pt_chars.append(ch)
    return "".join(pt_chars)
def vigenere_decrypt_letters_only(key: str, ciphertext: str) -> str:
    """
    Decrypt Vigenère but output only A–Z letters (uppercase).
    Non-letters in the ciphertext are ignored in the output (not kept).
    The key index still advances only on letters (standard behavior).
    """
    key_u = "".join([ch for ch in key.upper() if ch in ALPHABET])
    if not key_u:
        return ""
    out = []
    ki = 0
    for ch in ciphertext:
        ch_up = ch.upper()
        if ch_up in ALPHABET:
            k = ord(key_u[ki % len(key_u)]) - ord('A')
            c_idx = ord(ch_up) - ord('A')
            p_idx = (c_idx - k) % 26
            out.append(chr(ord('A') + p_idx))
            ki += 1
        else:
            # drop spaces/punct from output (do not append)
            continue
    return "".join(out)

def english_metrics_letters_only(text: str):
    """
    Metrics when output has no spaces/punct.
    Returns (letter_pct, chi2). 'letter_pct' is 100.0 if text is non-empty.
    """
    if not text:
        return 0.0, float("inf")
    letter_pct = 100.0  # by construction, output is letters only
    chi2 = chi_square_score(text)  # normalize() will keep it as-is
    return letter_pct, chi2


def _split_words(text: str):
    words = []
    cur = []
    for ch in text:
        if ch.isalpha():
            cur.append(ch.lower())
        else:
            if len(cur) > 0:
                words.append("".join(cur))
                cur = []
    if len(cur) > 0:
        words.append("".join(cur))
    return words

def _load_common_words() -> set:
    common_blob = '''
    the of and to in a is that be it for not on with he as you do at
    this but his by from they we say her she or an will my one all would there their what so up out if about who get which go me
    when make can like time no just him know take person into year your good some could them see other than then now look only come
    its over think also back after use two how our work first well way even new want because any these give day most us
    '''
    s = set()
    for w in common_blob.split():
        w = w.strip()
        if len(w) > 0:
            s.add(w)
    return s

COMMON_WORDS = _load_common_words()

def is_english(text: str, wordPercentage: int = WORD_PERCENTAGE, letterPercentage: int = LETTER_PERCENTAGE) -> bool:
    if not text:
        return False
    letters = sum(1 for ch in text if ch.isalpha() or ch == ' ')
    letter_pct = 100.0 * letters / max(1, len(text))
    if letter_pct < letterPercentage:
        return False
    words = _split_words(text)
    if len(words) == 0:
        return False
    matches = sum(1 for w in words if (w in COMMON_WORDS or len(w) >= 5))
    word_pct = 100.0 * matches / len(words)
    return word_pct >= wordPercentage

def english_metrics(text: str):
    if not text:
        return 0.0, 0.0, float("inf")
    letters = sum(1 for ch in text if ch.isalpha() or ch == ' ')
    letter_pct = 100.0 * letters / max(1, len(text))
    words = _split_words(text)
    if len(words) == 0:
        return 0.0, letter_pct, float("inf")
    matches = sum(1 for w in words if (w in COMMON_WORDS or len(w) >= 5))
    word_pct = 100.0 * matches / len(words)
    chi2 = chi_square_score(text)
    return word_pct, letter_pct, chi2

def hack_vigenere_dictionary_ranked(ciphertext: str,
                                    dict_lines: list,
                                    min_key_len: int = MIN_KEY_LEN,
                                    max_key_len: int = MAX_KEY_LEN,
                                    top_n: int = 5):
    # build candidate keys (letters only, upper)
    raw = []
    for line in dict_lines:
        w = line.strip()
        if not w:
            continue
        letters_only = "".join(ch for ch in w if ch.isalpha())
        if len(letters_only) < min_key_len or len(letters_only) > max_key_len:
            continue
        raw.append(letters_only.upper())

    keys = []
    seen = set()
    for u in raw:
        if u not in seen:
            seen.add(u)
            keys.append(u)

    # decrypt with letters-only output and score by chi-square (primary)
    scored = []
    for key in keys:
        pt_letters_only = vigenere_decrypt_letters_only(key, ciphertext)
        letter_pct, chi2 = english_metrics_letters_only(pt_letters_only)
        # filter: need a minimum length to be meaningful
        if len(pt_letters_only) >= 30:
            # Since we removed spaces, 'word_%' is not meaningful; expose 0.0
            scored.append((key, 0.0, chi2, pt_letters_only))

    # sort by chi-square ascending (lower is better)
    scored.sort(key=lambda t: t[2])
    return scored[:top_n]

# =============================
#           UI
# =============================
st.title("🔐 Classical Crypto Toolkit (Streamlit)")
st.caption("Caesar • Affine • Vigenère • Caesar Breaker • Vigenère Dictionary Attack")

with st.sidebar:
    st.header("Mode")
    mode = st.selectbox(
        "Choose a tool",
        ["Caesar (Encrypt/Decrypt)", "Affine (Encrypt/Decrypt)", "Vigenère (Encrypt/Decrypt)", "Break Caesar (chi-square)", "Vigenère Dictionary Attack (ranked)"]
    )
    st.divider()
    st.header("Utilities")
    show_metrics = st.checkbox("Show chi-square / metrics where relevant", value=True)

if mode == "Caesar (Encrypt/Decrypt)":
    st.subheader("Caesar Cipher")
    col1, col2 = st.columns(2)
    with col1:
        text = st.text_area("Input text", "We will meet at the park at eleven am", height=120)
        k = st.number_input("Key (0–25)", min_value=0, max_value=25, value=6, step=1)
        action = st.radio("Action", ["Encrypt", "Decrypt"], horizontal=True)
        go = st.button("Run Caesar")
    with col2:
        if go:
            if action == "Encrypt":
                out = caesar_encrypt(text, k)
            else:
                out = caesar_decrypt(text, k)
            st.code(out, language="text")
            if show_metrics:
                st.write(f"Chi-square: `{chi_square_score(out):.2f}`")

elif mode == "Affine (Encrypt/Decrypt)":
    st.subheader("Affine Cipher")
    col1, col2 = st.columns(2)
    with col1:
        text = st.text_area("Input text", "HELLO WORLD", height=120)
        a = st.number_input("a (coprime with 26)", min_value=1, max_value=25, value=5, step=1)
        b = st.number_input("b", min_value=0, max_value=25, value=8, step=1)
        action = st.radio("Action", ["Encrypt", "Decrypt"], horizontal=True)
        go = st.button("Run Affine")
    with col2:
        if go:
            try:
                out = affine_encrypt(text, a, b) if action == "Encrypt" else affine_decrypt(text, a, b)
                st.code(out, language="text")
                if show_metrics:
                    st.write(f"Chi-square: `{chi_square_score(out):.2f}`")
            except ValueError as e:
                st.error(str(e))

elif mode == "Vigenère (Encrypt/Decrypt)":
    st.subheader("Vigenère Cipher")
    col1, col2 = st.columns(2)
    with col1:
        text = st.text_area("Input text", "ATTACK AT DAWN", height=120)
        key = st.text_input("Key (letters only)", "LEMON")
        action = st.radio("Action", ["Encrypt", "Decrypt"], horizontal=True)
        go = st.button("Run Vigenère")
    with col2:
        if go:
            try:
                if action == "Encrypt":
                    out = vigenere_encrypt(text, key)
                else:
                    out = vigenere_decrypt(text, key)
                st.code(out, language="text")
                if show_metrics:
                    st.write(f"Chi-square: `{chi_square_score(out):.2f}`")
            except ValueError as e:
                st.error(str(e))

elif mode == "Break Caesar (chi-square)":
    st.subheader("Break Caesar (Frequency Analysis)")
    ct = st.text_area("Ciphertext", "Ck crru skkz gz znk vgxq gz krobkx gs", height=160)
    if st.button("Break"):
        best_k, best_pt, best_score = break_caesar(ct)
        st.success(f"Recovered key: {best_k}")
        st.code(best_pt, language="text")
        if show_metrics:
            st.write(f"Chi-square: `{best_score:.2f}`")

elif mode == "Vigenère Dictionary Attack (ranked)":
    st.subheader("Vigenère Dictionary Attack (Ranked)")
    st.write("Upload a dictionary (one word per line). The attack decrypts to **letters only** (spaces/punct are removed) and ranks by chi-square.")
    sample_ct = st.text_area("Ciphertext", "Cecr esi vlvsmbrtr zls zmcuwgzbyk, avrtrbif iezgmbj, hbcijvr vstffbnhps, dufz fs khr zvikh.", height=160)
    uploaded = st.file_uploader("dictionary.txt", type=["txt"])
    top_n = st.slider("Top candidates to show", 1, 20, 5)

    # Optional quick dictionary text
    dict_text = st.text_area("Or paste dictionary words (one per line)", "", height=120, help="If provided, this will be combined with the uploaded file.")

    if st.button("Run dictionary attack"):
        dict_lines = []
        if uploaded is not None:
            dict_lines.extend(uploaded.getvalue().decode("utf-8", errors="ignore").splitlines())
        if dict_text.strip():
            dict_lines.extend(dict_text.splitlines())

        if not dict_lines:
            st.warning("Please upload or paste a dictionary first.")
        else:
            results = hack_vigenere_dictionary_ranked(sample_ct, dict_lines=dict_lines, top_n=top_n)
            if not results:
                st.info("No candidates found. Try a larger dictionary or adjust your text.")
            else:
                df = pd.DataFrame([
                    {"rank": i+1, "key": key, "word_%": f"{word_pct:.1f}", "chi2": round(chi2, 2), "preview": pt[:120]}
                    for i, (key, word_pct, chi2, pt) in enumerate(results)
                ])
                st.dataframe(df, use_container_width=True)
                best_key, best_word, best_chi2, best_plain = results[0]
                st.markdown("**Best candidate**")
                st.write(f"Key: `{best_key}` — word%: `{best_word:.1f}` — chi²: `{best_chi2:.2f}`")
                st.code(best_plain, language="text")
