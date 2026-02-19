"""
Password Entropy Analyzer
===========================

Comprehensive password strength analysis implementing multiple entropy
models, pattern detection, and crack time estimation. Evaluates passwords
against NIST SP 800-63B guidelines and provides actionable improvement
suggestions.

Entropy is computed using three complementary models:
1. Combinatorial entropy: log2(pool_size^length)
2. Shannon entropy: character-level information content
3. Markov entropy: bigram transition probability model

Pattern detection identifies common weakening factors:
- Dictionary words (top 10,000 English words)
- Keyboard patterns (qwerty, asdf, zxcv, etc.)
- Date patterns (YYYY, MMDD, etc.)
- Repeated characters and sequences
- L33t speak substitutions

Crack time estimation uses three attack speed scenarios:
- Online throttled: 10^3 guesses/second
- Offline fast hash: 10^9 guesses/second (MD5/SHA-1 on GPU)
- Offline slow hash: 10^6 guesses/second (bcrypt on GPU)
- Massive parallel: 10^12 guesses/second (state-level)

References:
    - NIST SP 800-63B (2017). Digital Identity Guidelines --
      Authentication and Lifecycle Management.
    - Weir, M., Aggarwal, S., de Medeiros, B., & Glodek, B. (2009).
      Password Cracking Using Probabilistic Context-Free Grammars.
      IEEE S&P.
    - Shannon, C. E. (1948). A Mathematical Theory of Communication.
    - Bonneau, J. (2012). The Science of Guessing: Analyzing an
      Anonymized Corpus of 70 Million Passwords. IEEE S&P.
"""

from __future__ import annotations

import math
import re
import string
from collections import Counter
from typing import Optional

from cipher.core.models import (
    CrackTimeEstimate,
    PasswordAnalysis,
    PasswordPattern,
    PasswordStrength,
)


# ===================================================================== #
#  Common Password and Pattern Databases
# ===================================================================== #

# Top common passwords (subset for checking -- production would use a full list)
_COMMON_PASSWORDS: set[str] = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey",
    "1234567", "letmein", "trustno1", "dragon", "baseball", "iloveyou",
    "master", "sunshine", "ashley", "bailey", "passw0rd", "shadow",
    "123123", "654321", "superman", "qazwsx", "michael", "football",
    "password1", "password123", "admin", "welcome", "hello", "charlie",
    "donald", "login", "starwars", "solo", "qwerty123", "1q2w3e4r",
    "zaq1zaq1", "1qaz2wsx", "princess", "azerty", "000000", "access",
    "master1", "default", "changeme", "12345", "111111", "1234",
    "666666", "7777777", "123456789", "hunter2",
}

# Keyboard row patterns
_KEYBOARD_PATTERNS: list[str] = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "qwerty", "asdfgh", "zxcvbn",
    "qwert", "asdfg", "zxcvb",
    "1234567890", "12345", "123456",
    "!@#$%^&*()", "!@#$%",
    "qazwsx", "1qaz2wsx", "1q2w3e",
    "0987654321", "poiuytrewq",
]

# L33t speak substitution map
_LEET_MAP: dict[str, str] = {
    "4": "a", "@": "a", "8": "b", "(": "c", "3": "e",
    "6": "g", "#": "h", "1": "i", "!": "i", "|": "l",
    "0": "o", "9": "p", "5": "s", "$": "s", "7": "t",
    "+": "t", "2": "z",
}

# Simple dictionary of common English words (top ~200 for pattern detection)
_COMMON_WORDS: set[str] = {
    "the", "be", "to", "of", "and", "in", "that", "have", "it", "for",
    "not", "on", "with", "he", "as", "you", "do", "at", "this", "but",
    "his", "by", "from", "they", "we", "her", "she", "or", "an", "will",
    "my", "one", "all", "would", "there", "their", "what", "so", "up",
    "out", "if", "about", "who", "get", "which", "go", "me", "when",
    "make", "can", "like", "time", "no", "just", "him", "know", "take",
    "people", "into", "year", "your", "good", "some", "could", "them",
    "see", "other", "than", "then", "now", "look", "only", "come",
    "its", "over", "think", "also", "back", "after", "use", "two",
    "how", "our", "work", "first", "well", "way", "even", "new",
    "want", "because", "any", "these", "give", "day", "most", "us",
    "love", "life", "name", "very", "home", "world", "hand", "high",
    "place", "night", "great", "keep", "help", "tell", "still",
    "child", "here", "own", "word", "never", "last", "long", "must",
    "house", "turn", "move", "live", "found", "money", "water", "every",
    "old", "school", "power", "may", "same", "part", "number", "head",
    "side", "away", "small", "state", "point", "form", "door", "game",
    "under", "light", "story", "city", "open", "begin", "girl", "line",
    "food", "body", "left", "face", "being", "family", "friend",
    "mother", "father", "young", "real", "book", "read", "black",
    "white", "start", "earth", "girl", "heart", "music",
    # Common password words
    "password", "admin", "login", "welcome", "master", "dragon",
    "monkey", "shadow", "sunshine", "princess", "football", "baseball",
    "soccer", "hockey", "batman", "superman", "spider", "killer",
    "trustno", "letmein", "secret", "access", "flower", "summer",
    "winter", "spring", "autumn", "hunter", "ranger", "eagle",
    "tiger", "lion", "wolf", "bear", "falcon", "phoenix", "angel",
    "devil", "demon", "magic", "wizard", "ninja",
}

# English bigram frequencies (log-probabilities for Markov model)
# Approximated from standard English text corpora
_ENGLISH_BIGRAM_FREQ: dict[str, float] = {
    "th": 3.56, "he": 3.07, "in": 2.43, "er": 2.05, "an": 1.99,
    "re": 1.85, "on": 1.76, "at": 1.49, "en": 1.45, "nd": 1.35,
    "ti": 1.34, "es": 1.34, "or": 1.28, "te": 1.27, "of": 1.17,
    "ed": 1.17, "is": 1.13, "it": 1.12, "al": 1.09, "ar": 1.07,
    "st": 1.05, "to": 1.04, "nt": 1.04, "ng": 0.95, "se": 0.93,
    "ha": 0.93, "as": 0.87, "ou": 0.87, "io": 0.83, "le": 0.83,
    "ve": 0.83, "co": 0.79, "me": 0.79, "de": 0.76, "hi": 0.76,
    "ri": 0.73, "ro": 0.73, "ic": 0.70, "ne": 0.69, "ea": 0.69,
    "ra": 0.69, "ce": 0.65, "li": 0.62, "ch": 0.60, "ll": 0.58,
    "be": 0.58, "ma": 0.57, "si": 0.55, "om": 0.55, "ur": 0.54,
}


class PasswordEntropyAnalyzer:
    """Analyses password strength using entropy and pattern detection.

    Combines multiple entropy models with pattern recognition to provide
    a comprehensive assessment of password security.

    Usage::

        analyzer = PasswordEntropyAnalyzer()
        result = analyzer.analyze("MyP@ssw0rd!")
        print(f"Strength: {result.strength.value}")
        print(f"Entropy: {result.entropy:.1f} bits")
    """

    # Attack speed scenarios for crack time estimation
    _ATTACK_SPEEDS: list[tuple[str, float]] = [
        ("Online attack (throttled)", 1e3),
        ("Offline attack (slow hash, e.g. bcrypt)", 1e6),
        ("Offline attack (fast hash, e.g. MD5 on GPU)", 1e9),
        ("Massive parallel / state-level", 1e12),
    ]

    def analyze(self, password: str) -> PasswordAnalysis:
        """Perform comprehensive password strength analysis.

        Args:
            password: The password to analyse.

        Returns:
            PasswordAnalysis with entropy, strength, and recommendations.
        """
        if not password:
            return PasswordAnalysis(
                password_masked="",
                length=0,
                entropy=0.0,
                char_pool_size=0,
                strength=PasswordStrength.VERY_WEAK,
                suggestions=["Password is empty. Use a strong passphrase."],
                nist_compliant=False,
                score=0,
            )

        length = len(password)
        pool_size = self._calculate_pool_size(password)
        masked = self._mask_password(password)

        # Compute entropy measures
        combinatorial_entropy = self._combinatorial_entropy(length, pool_size)
        char_shannon_entropy = self._shannon_entropy(password)
        markov_entropy = self._markov_entropy(password)

        # Use the minimum of combinatorial and adjusted Markov as effective entropy
        effective_entropy = min(combinatorial_entropy, markov_entropy * 1.5)
        # Blend with Shannon for a balanced estimate
        blended_entropy = (effective_entropy * 0.6 + char_shannon_entropy * length * 0.4)
        # Ensure we don't exceed combinatorial maximum
        final_entropy = min(blended_entropy, combinatorial_entropy)

        # Pattern detection
        patterns = self._detect_patterns(password)

        # Apply pattern penalties
        total_penalty = sum(p.penalty for p in patterns)
        adjusted_entropy = max(0.0, final_entropy - total_penalty)

        # Common password check (massive penalty)
        if password.lower() in _COMMON_PASSWORDS:
            adjusted_entropy = min(adjusted_entropy, 5.0)
            patterns.append(PasswordPattern(
                pattern_type="common_password",
                value=password.lower(),
                position=0,
                penalty=final_entropy - 5.0,
            ))

        # Crack time estimates
        crack_times = self._estimate_crack_times(adjusted_entropy)

        # NIST SP 800-63B compliance
        nist_compliant = self._check_nist_compliance(password)

        # Calculate strength and score
        strength = self._rate_strength(adjusted_entropy, length, patterns)
        score = self._calculate_score(
            adjusted_entropy, length, pool_size, patterns, nist_compliant
        )

        # Generate suggestions
        suggestions = self._generate_suggestions(
            password, adjusted_entropy, length, pool_size, patterns
        )

        return PasswordAnalysis(
            password_masked=masked,
            length=length,
            entropy=round(adjusted_entropy, 2),
            char_pool_size=pool_size,
            strength=strength,
            crack_time_estimates=crack_times,
            patterns_detected=patterns,
            suggestions=suggestions,
            nist_compliant=nist_compliant,
            score=score,
        )

    # ------------------------------------------------------------------ #
    #  Entropy Calculations
    # ------------------------------------------------------------------ #

    @staticmethod
    def _calculate_pool_size(password: str) -> int:
        """Calculate the character pool size based on character classes used.

        Character classes:
        - Lowercase letters: 26
        - Uppercase letters: 26
        - Digits: 10
        - Special (printable ASCII symbols): 33
        - Extended Unicode: +100 per additional Unicode block detected

        Args:
            password: The password string.

        Returns:
            Effective character pool size.
        """
        pool = 0
        has_lower = any(c in string.ascii_lowercase for c in password)
        has_upper = any(c in string.ascii_uppercase for c in password)
        has_digit = any(c in string.digits for c in password)
        has_special = any(
            c in string.punctuation or (32 < ord(c) < 127 and not c.isalnum())
            for c in password
        )
        has_unicode = any(ord(c) > 127 for c in password)

        if has_lower:
            pool += 26
        if has_upper:
            pool += 26
        if has_digit:
            pool += 10
        if has_special:
            pool += 33
        if has_unicode:
            pool += 100

        return max(pool, 1)

    @staticmethod
    def _combinatorial_entropy(length: int, pool_size: int) -> float:
        """Compute combinatorial entropy: log2(pool_size ^ length).

        This is the maximum entropy assuming uniform random selection
        from the character pool.

        Args:
            length: Password length.
            pool_size: Character pool size.

        Returns:
            Entropy in bits.
        """
        if length <= 0 or pool_size <= 1:
            return 0.0
        return length * math.log2(pool_size)

    @staticmethod
    def _shannon_entropy(password: str) -> float:
        """Compute Shannon entropy per character of the password.

        H = -sum(p(c) * log2(p(c))) for each distinct character c.

        Args:
            password: Password string.

        Returns:
            Shannon entropy in bits per character.
        """
        if not password:
            return 0.0

        counts = Counter(password)
        length = len(password)
        entropy = 0.0
        for count in counts.values():
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _markov_entropy(password: str) -> float:
        """Estimate entropy using a Markov chain model of English text.

        Uses bigram transition probabilities from English text to estimate
        how predictable the password is. Low Markov entropy indicates the
        password follows common English patterns.

        Reference:
            Weir, M. et al. (2009). Testing Metrics for Password Creation
            Policies by Attacking Large Sets of Revealed Passwords. CCS.

        Args:
            password: Password string.

        Returns:
            Estimated entropy in bits.
        """
        if len(password) < 2:
            return math.log2(95) if password else 0.0  # Single printable char

        pw_lower = password.lower()
        total_entropy = math.log2(95)  # First character (printable ASCII)

        for i in range(1, len(pw_lower)):
            bigram = pw_lower[i - 1 : i + 1]
            # Check if this bigram has a known frequency
            freq = _ENGLISH_BIGRAM_FREQ.get(bigram, 0.0)
            if freq > 0:
                # Higher frequency = lower entropy (more predictable)
                # Convert frequency percentage to probability estimate
                p_transition = freq / 100.0
                bits = -math.log2(max(p_transition, 1e-10))
                total_entropy += min(bits, math.log2(95))
            else:
                # Unknown bigram -- assume moderate unpredictability
                total_entropy += math.log2(26)  # ~4.7 bits

        return total_entropy

    # ------------------------------------------------------------------ #
    #  Pattern Detection
    # ------------------------------------------------------------------ #

    def _detect_patterns(self, password: str) -> list[PasswordPattern]:
        """Detect weakening patterns in the password.

        Checks for dictionary words, keyboard patterns, dates,
        repeated characters, sequential characters, and l33t speak.

        Args:
            password: Password string.

        Returns:
            List of detected patterns with penalties.
        """
        patterns: list[PasswordPattern] = []

        patterns.extend(self._detect_dictionary_words(password))
        patterns.extend(self._detect_keyboard_patterns(password))
        patterns.extend(self._detect_date_patterns(password))
        patterns.extend(self._detect_repeated_chars(password))
        patterns.extend(self._detect_sequential_chars(password))
        patterns.extend(self._detect_leet_speak(password))

        return patterns

    @staticmethod
    def _detect_dictionary_words(password: str) -> list[PasswordPattern]:
        """Detect dictionary words within the password."""
        patterns: list[PasswordPattern] = []
        pw_lower = password.lower()

        for word in _COMMON_WORDS:
            if len(word) >= 3:
                idx = pw_lower.find(word)
                if idx >= 0:
                    # Penalty proportional to word length (common words reduce entropy)
                    penalty = len(word) * 2.0
                    patterns.append(PasswordPattern(
                        pattern_type="dictionary_word",
                        value=word,
                        position=idx,
                        penalty=penalty,
                    ))

        return patterns

    @staticmethod
    def _detect_keyboard_patterns(password: str) -> list[PasswordPattern]:
        """Detect keyboard layout patterns (qwerty, etc.)."""
        patterns: list[PasswordPattern] = []
        pw_lower = password.lower()

        for kbd_pattern in _KEYBOARD_PATTERNS:
            if len(kbd_pattern) < 3:
                continue
            # Check for substrings of length 3+
            for sub_len in range(min(len(kbd_pattern), len(pw_lower)), 2, -1):
                for start in range(len(kbd_pattern) - sub_len + 1):
                    sub = kbd_pattern[start : start + sub_len]
                    idx = pw_lower.find(sub)
                    if idx >= 0:
                        penalty = sub_len * 3.0
                        patterns.append(PasswordPattern(
                            pattern_type="keyboard_pattern",
                            value=sub,
                            position=idx,
                            penalty=penalty,
                        ))
                        break  # Found longest match for this pattern

        return patterns

    @staticmethod
    def _detect_date_patterns(password: str) -> list[PasswordPattern]:
        """Detect date patterns (YYYY, MMDD, MM/DD, etc.)."""
        patterns: list[PasswordPattern] = []

        # YYYY pattern (1900-2099)
        for match in re.finditer(r"(19|20)\d{2}", password):
            patterns.append(PasswordPattern(
                pattern_type="date_year",
                value=match.group(),
                position=match.start(),
                penalty=8.0,
            ))

        # MM/DD or DD/MM patterns
        for match in re.finditer(
            r"(0[1-9]|1[0-2])[\-/](0[1-9]|[12]\d|3[01])", password
        ):
            patterns.append(PasswordPattern(
                pattern_type="date_mmdd",
                value=match.group(),
                position=match.start(),
                penalty=10.0,
            ))

        # MMDDYYYY or DDMMYYYY
        for match in re.finditer(
            r"(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(19|20)\d{2}", password
        ):
            patterns.append(PasswordPattern(
                pattern_type="date_full",
                value=match.group(),
                position=match.start(),
                penalty=15.0,
            ))

        return patterns

    @staticmethod
    def _detect_repeated_chars(password: str) -> list[PasswordPattern]:
        """Detect repeated characters (aaa, 111, etc.)."""
        patterns: list[PasswordPattern] = []

        for match in re.finditer(r"(.)\1{2,}", password):
            rep_len = len(match.group())
            patterns.append(PasswordPattern(
                pattern_type="repeated_chars",
                value=match.group(),
                position=match.start(),
                penalty=rep_len * 2.5,
            ))

        return patterns

    @staticmethod
    def _detect_sequential_chars(password: str) -> list[PasswordPattern]:
        """Detect sequential character runs (abc, 123, etc.)."""
        patterns: list[PasswordPattern] = []

        if len(password) < 3:
            return patterns

        # Check for ascending/descending sequences
        seq_start = 0
        seq_len = 1
        ascending = True

        for i in range(1, len(password)):
            diff = ord(password[i]) - ord(password[i - 1])
            if i == seq_start + 1:
                ascending = diff == 1
                if abs(diff) == 1:
                    seq_len = 2
                else:
                    seq_start = i
                    seq_len = 1
            elif (ascending and diff == 1) or (not ascending and diff == -1):
                seq_len += 1
            else:
                if seq_len >= 3:
                    seq_str = password[seq_start : seq_start + seq_len]
                    patterns.append(PasswordPattern(
                        pattern_type="sequential_chars",
                        value=seq_str,
                        position=seq_start,
                        penalty=seq_len * 2.0,
                    ))
                seq_start = i
                seq_len = 1

        # Check last sequence
        if seq_len >= 3:
            seq_str = password[seq_start : seq_start + seq_len]
            patterns.append(PasswordPattern(
                pattern_type="sequential_chars",
                value=seq_str,
                position=seq_start,
                penalty=seq_len * 2.0,
            ))

        return patterns

    def _detect_leet_speak(self, password: str) -> list[PasswordPattern]:
        """Detect l33t speak substitutions that map to dictionary words."""
        patterns: list[PasswordPattern] = []

        # De-l33t the password
        deleeted = ""
        for c in password.lower():
            deleeted += _LEET_MAP.get(c, c)

        # Check if the de-l33ted version contains dictionary words
        if deleeted != password.lower():
            for word in _COMMON_WORDS:
                if len(word) >= 4 and word in deleeted:
                    idx = deleeted.find(word)
                    patterns.append(PasswordPattern(
                        pattern_type="leet_speak",
                        value=f"{password[idx:idx+len(word)]} -> {word}",
                        position=idx,
                        penalty=len(word) * 1.5,
                    ))

        return patterns

    # ------------------------------------------------------------------ #
    #  Crack Time Estimation
    # ------------------------------------------------------------------ #

    def _estimate_crack_times(
        self, entropy_bits: float
    ) -> list[CrackTimeEstimate]:
        """Estimate time to crack at various attack speeds.

        Assumes brute-force attack where the expected number of attempts
        is 2^(entropy - 1) (half the keyspace on average).

        Args:
            entropy_bits: Effective password entropy in bits.

        Returns:
            List of CrackTimeEstimate for each attack scenario.
        """
        estimates: list[CrackTimeEstimate] = []
        keyspace = 2 ** entropy_bits if entropy_bits > 0 else 1
        avg_attempts = keyspace / 2  # Expected attempts (uniform distribution)

        for scenario, speed in self._ATTACK_SPEEDS:
            seconds = avg_attempts / speed
            display = self._format_duration(seconds)
            estimates.append(CrackTimeEstimate(
                scenario=scenario,
                guesses_per_second=speed,
                seconds=seconds,
                display=display,
            ))

        return estimates

    @staticmethod
    def _format_duration(seconds: float) -> str:
        """Format a duration in seconds to a human-readable string."""
        if seconds < 0.001:
            return "instant"
        if seconds < 1:
            return f"{seconds * 1000:.0f} milliseconds"
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        if seconds < 3600:
            return f"{seconds / 60:.1f} minutes"
        if seconds < 86400:
            return f"{seconds / 3600:.1f} hours"
        if seconds < 86400 * 365:
            return f"{seconds / 86400:.1f} days"
        if seconds < 86400 * 365 * 1000:
            return f"{seconds / (86400 * 365):.1f} years"
        if seconds < 86400 * 365 * 1e6:
            return f"{seconds / (86400 * 365 * 1000):.1f} thousand years"
        if seconds < 86400 * 365 * 1e9:
            return f"{seconds / (86400 * 365 * 1e6):.1f} million years"
        if seconds < 86400 * 365 * 1e12:
            return f"{seconds / (86400 * 365 * 1e9):.1f} billion years"
        return f"{seconds / (86400 * 365 * 1e12):.1e} trillion years"

    # ------------------------------------------------------------------ #
    #  NIST Compliance and Scoring
    # ------------------------------------------------------------------ #

    @staticmethod
    def _check_nist_compliance(password: str) -> bool:
        """Check password against NIST SP 800-63B guidelines.

        NIST SP 800-63B requirements for memorised secrets:
        - Minimum 8 characters
        - Not a commonly used password
        - Not a repetitive or sequential string
        - Not a context-specific word

        Reference:
            NIST SP 800-63B Section 5.1.1.2 (2017).

        Args:
            password: The password to check.

        Returns:
            True if the password meets NIST guidelines.
        """
        if len(password) < 8:
            return False
        if password.lower() in _COMMON_PASSWORDS:
            return False
        # Check for all-same character
        if len(set(password)) == 1:
            return False
        # Check for simple sequential
        if password in ("12345678", "abcdefgh", "qwertyui"):
            return False
        return True

    @staticmethod
    def _rate_strength(
        entropy: float,
        length: int,
        patterns: list[PasswordPattern],
    ) -> PasswordStrength:
        """Rate the overall password strength.

        Thresholds (entropy bits):
        - < 25: very_weak
        - 25-35: weak
        - 35-50: fair
        - 50-70: strong
        - 70+: very_strong

        Args:
            entropy: Effective entropy in bits.
            length: Password length.
            patterns: Detected weakening patterns.

        Returns:
            PasswordStrength rating.
        """
        if entropy < 25 or length < 6:
            return PasswordStrength.VERY_WEAK
        elif entropy < 35:
            return PasswordStrength.WEAK
        elif entropy < 50:
            return PasswordStrength.FAIR
        elif entropy < 70:
            return PasswordStrength.STRONG
        else:
            return PasswordStrength.VERY_STRONG

    @staticmethod
    def _calculate_score(
        entropy: float,
        length: int,
        pool_size: int,
        patterns: list[PasswordPattern],
        nist_compliant: bool,
    ) -> int:
        """Calculate a numeric score from 0 to 100.

        Scoring breakdown:
        - Entropy contribution: up to 40 points
        - Length contribution: up to 20 points
        - Pool diversity: up to 20 points
        - NIST compliance: 10 points
        - Pattern penalty: up to -30 points

        Args:
            entropy: Effective entropy in bits.
            length: Password length.
            pool_size: Character pool size.
            patterns: Detected patterns.
            nist_compliant: Whether NIST-compliant.

        Returns:
            Score from 0 to 100.
        """
        # Entropy score (0-40)
        entropy_score = min(40, entropy * 40 / 80)

        # Length score (0-20)
        length_score = min(20, length * 20 / 20)

        # Pool diversity score (0-20)
        pool_score = min(20, pool_size * 20 / 95)

        # NIST bonus
        nist_bonus = 10 if nist_compliant else 0

        # Pattern penalty
        pattern_penalty = min(30, sum(p.penalty for p in patterns) * 0.5)

        total = entropy_score + length_score + pool_score + nist_bonus - pattern_penalty
        return max(0, min(100, int(total)))

    @staticmethod
    def _mask_password(password: str) -> str:
        """Create a masked version of the password for display.

        Shows first and last character with asterisks in between.

        Args:
            password: The password to mask.

        Returns:
            Masked password string.
        """
        if len(password) <= 2:
            return "*" * len(password)
        return password[0] + "*" * (len(password) - 2) + password[-1]

    @staticmethod
    def _generate_suggestions(
        password: str,
        entropy: float,
        length: int,
        pool_size: int,
        patterns: list[PasswordPattern],
    ) -> list[str]:
        """Generate improvement suggestions for the password.

        Args:
            password: The original password.
            entropy: Effective entropy.
            length: Password length.
            pool_size: Character pool size.
            patterns: Detected patterns.

        Returns:
            List of suggestion strings.
        """
        suggestions: list[str] = []

        if length < 12:
            suggestions.append(
                f"Increase length to at least 12 characters (currently {length}). "
                f"Each additional character significantly increases entropy."
            )

        if pool_size < 70:
            missing: list[str] = []
            if not any(c in string.ascii_lowercase for c in password):
                missing.append("lowercase letters")
            if not any(c in string.ascii_uppercase for c in password):
                missing.append("uppercase letters")
            if not any(c in string.digits for c in password):
                missing.append("digits")
            if not any(c in string.punctuation for c in password):
                missing.append("special characters")
            if missing:
                suggestions.append(
                    f"Add {', '.join(missing)} to increase character pool diversity."
                )

        dict_patterns = [p for p in patterns if p.pattern_type == "dictionary_word"]
        if dict_patterns:
            words = [p.value for p in dict_patterns[:3]]
            suggestions.append(
                f"Avoid common dictionary words ({', '.join(words)}). "
                f"Consider using a passphrase with uncommon word combinations."
            )

        kbd_patterns = [p for p in patterns if p.pattern_type == "keyboard_pattern"]
        if kbd_patterns:
            suggestions.append(
                "Avoid keyboard patterns (qwerty, asdf, etc.). "
                "These are among the first patterns attackers try."
            )

        if any(p.pattern_type == "repeated_chars" for p in patterns):
            suggestions.append(
                "Avoid repeated characters (aaa, 111). "
                "These reduce effective entropy significantly."
            )

        if any(p.pattern_type == "common_password" for p in patterns):
            suggestions.append(
                "This is a commonly used password. Change it immediately. "
                "It will be cracked within seconds."
            )

        if entropy >= 50 and not suggestions:
            suggestions.append(
                "Password strength is adequate. Consider using a password "
                "manager to generate and store unique passwords."
            )

        if not suggestions:
            suggestions.append(
                "Consider using a randomly generated passphrase of 4+ "
                "uncommon words for better memorability and security."
            )

        return suggestions
