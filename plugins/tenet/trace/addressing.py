"""
FRINET address resolution: map trace offsets onto the open database.

This module is **disassembler agnostic** on purpose: it only deals with
plain data (segment layouts, sampled ``off`` values, image names) so it can
be unit tested without IDA. The IDA side of the bridge lives in
``tenet.integration.api.ida_api`` and the wiring in ``tenet.trace.analysis``.

Vocabulary (kept deliberately distinct):

``pc``
    the runtime instruction pointer of an event, exactly as it was
    executed on the device (``pc``/``rip``/``eip`` field of the trace).
``slide``
    the runtime base of the traced module (``slide=0x...`` header).
``off``
    ``pc - slide``; only present for events inside the traced module.
``idb_module_start``
    the effective address of ``off == 0`` inside the *open* database. This
    is *not* necessarily ``ida_nalt.get_imagebase()``: ELF/Android images
    frequently have segments whose real origin differs from the nominal
    imagebase (rebases, partial loaders, headers not mapped as segments).
``static_ea``
    ``idb_module_start + off`` -- where the event lives in the IDB.
"""

import os
import re

#: image identity match quality
MATCH_EXACT = "exact"
MATCH_POSSIBLE = "possible"
MATCH_MISMATCH = "mismatch"
MATCH_UNKNOWN = "unknown"

#: scoring
AMBIGUITY_RATIO = 0.90     # a runner-up this close to the winner is a tie
MIN_ACCEPT_SCORE = 0.50    # below this the winner is not trustworthy

#
# an image *name* mismatch is a soft signal (binaries get renamed, stripped
# of their original filename, or opened in an IDB saved under another name),
# whereas offsets that land squarely in the database are hard evidence. When
# the structural evidence is overwhelming -- a single candidate, every
# sampled offset mapped, and a healthy number of those in code -- the name
# mismatch alone must not block resolution. It is still reported, loudly.
#
MIN_TRUST_SAMPLES = 16     # too few samples to override a name mismatch
MIN_TRUST_CODE_HITS = 8    # ... and they must include real code addresses

# priority used to break exact score ties (structural evidence > assumption)
SOURCE_PRIORITY = {
    "imagebase": 0,
}


#-------------------------------------------------------------------------
# Image identity
#-------------------------------------------------------------------------

def normalize_image_name(name):
    """Normalize an image/process name for comparison (basename, lowercase)."""
    if not name:
        return ""
    name = str(name).replace("\\", "/").strip()
    return os.path.basename(name).lower()


def module_name_from_trace_filename(path):
    """
    Recover the traced image/process name from a trace filename.

    The tracer writes ``<procname>_<epoch>_<tid>.frinet``, where
    *procname* is the basename of the spawned program (or the process name
    used when attaching). Returns ``None`` when the name does not follow
    that pattern.
    """
    if not path:
        return None
    basename = normalize_image_name(path)
    match = re.match(r"^(?P<name>.+?)_(\d{6,})_(\d+)(?:\.(?:frinet|tenet))?$", basename)
    if not match:
        return None
    return match.group("name")


def names_match(trace_image, db_image):
    """
    Compare the traced image with the image open in the disassembler.

    Returns one of ``MATCH_EXACT`` / ``MATCH_POSSIBLE`` / ``MATCH_MISMATCH``
    / ``MATCH_UNKNOWN``.
    """
    left = normalize_image_name(trace_image)
    right = normalize_image_name(db_image)

    if not left or not right:
        return MATCH_UNKNOWN
    if left == right:
        return MATCH_EXACT

    # versioned libraries / cosmetic differences (libfoo.so vs libfoo.so.1)
    shorter, longer = sorted((left, right), key=len)
    if longer.startswith(shorter) and len(shorter) >= 4:
        return MATCH_POSSIBLE

    return MATCH_MISMATCH


class ImageIdentity(object):
    """Result of comparing the trace's image with the open database."""

    def __init__(self, trace_image, db_image, match=MATCH_UNKNOWN):
        self.trace_image = trace_image
        self.db_image = db_image
        self.match = match

    @property
    def trusted(self):
        return self.match in (MATCH_EXACT, MATCH_POSSIBLE)

    def __repr__(self):
        return (f"ImageIdentity(trace={self.trace_image!r}, db={self.db_image!r}, "
                f"match={self.match!r})")


def identify_image(trace_filepath, root_filename):
    """Return an :class:`ImageIdentity` for a trace file vs an open database."""
    trace_image = module_name_from_trace_filename(trace_filepath)
    db_image = normalize_image_name(root_filename)
    return ImageIdentity(trace_image, db_image, names_match(trace_image, db_image))


#-------------------------------------------------------------------------
# Segments
#-------------------------------------------------------------------------

class SegmentInfo(object):
    """A disassembler-agnostic view of one segment of the open database."""

    def __init__(self, name, start, end, filepos=-1, executable=False):
        self.name = name
        self.start = start
        self.end = end
        #: offset of the beginning of the segment inside the input file,
        #: ``-1`` when the disassembler does not provide it
        self.filepos = filepos
        self.executable = executable

    @property
    def size(self):
        return max(0, self.end - self.start)

    @property
    def origin(self):
        """
        The effective address at which ``off == 0`` would land for this
        segment, assuming the module offset equals the file offset.

        Only meaningful when the segment knows its file position.
        """
        if self.filepos is None or self.filepos < 0:
            return None
        return self.start - self.filepos

    def contains(self, ea):
        return self.start <= ea < self.end

    def offset_to_ea(self, off):
        """Translate an offset with this segment as the origin (or None)."""
        origin = self.origin
        if origin is None:
            return None
        ea = origin + off
        return ea if self.contains(ea) else None

    def __repr__(self):
        kind = "code" if self.executable else "data"
        return (f"SegmentInfo({self.name!r}, 0x{self.start:X}-0x{self.end:X}, "
                f"{kind}, filepos={self.filepos})")


#-------------------------------------------------------------------------
# Origin resolution
#-------------------------------------------------------------------------

class OriginCandidate(object):
    """A candidate for ``idb_module_start`` (the address of ``off == 0``)."""

    def __init__(self, ea, source, score=0.0, hits=0, code_hits=0, total=0):
        self.ea = ea
        self.source = source
        self.score = score
        self.hits = hits
        self.code_hits = code_hits
        self.total = total

    @property
    def priority(self):
        return SOURCE_PRIORITY.get(self.source.split(":")[0], 1)

    @property
    def sort_key(self):
        # higher score, then more code hits, then structural evidence
        return (round(self.score, 6), self.code_hits, self.priority)

    def describe(self):
        return (f"0x{self.ea:X}  ({self.source}, "
                f"{self.hits}/{self.total} offsets mapped, "
                f"{self.code_hits} in code)")

    def __repr__(self):
        return f"OriginCandidate(0x{self.ea:X}, {self.source!r}, score={self.score:0.2f})"


class Resolution(object):
    """Outcome of resolving ``off == 0`` against the open database."""

    def __init__(self, origin=None, source=None, candidates=None,
                 ambiguous=False, reason="", identity=None):
        self.origin = origin
        self.source = source
        self.candidates = candidates or []
        self.ambiguous = ambiguous
        self.reason = reason
        self.identity = identity

    @property
    def resolved(self):
        return self.origin is not None

    def to_ea(self, off):
        """``static_ea = idb_module_start + off`` (or None)."""
        if self.origin is None or off is None:
            return None
        return self.origin + off

    def __repr__(self):
        return (f"Resolution(origin={self.origin and hex(self.origin)}, "
                f"source={self.source!r}, ambiguous={self.ambiguous}, "
                f"reason={self.reason!r})")


class OffsetResolver(object):
    """
    Decide where ``off == 0`` lives in the database, then translate.

    The candidate origins are:

    * the nominal imagebase, and
    * ``segment.start - segment.filepos`` for every segment that knows its
      file position (this is what makes rebased / partial databases work).

    Every candidate is scored by sampling the offsets that actually occur
    in the trace and counting how many land inside a mapped (and, better,
    code) address. Ties, low scores and image identity mismatches are
    *ambiguous*: they are either confirmed through ``prompt`` or refused
    (``origin is None``), because guessing wrong would silently map the
    whole trace to the wrong place.
    """

    def __init__(self, segments, sample_offs, imagebase=None, identity=None,
                 is_mapped=None, is_code=None, prompt=None):
        self.segments = list(segments or [])
        self.sample_offs = list(sample_offs or [])
        self.imagebase = imagebase
        self.identity = identity
        self.is_mapped = is_mapped
        self.is_code = is_code
        self.prompt = prompt

    #-- candidates -------------------------------------------------------
    def candidates(self):
        """Return the deduplicated candidate origins, best first."""
        found = {}

        if self.imagebase is not None:
            found[self.imagebase] = OriginCandidate(self.imagebase, "imagebase")

        for seg in self.segments:
            origin = seg.origin
            if origin is None:
                continue
            candidate = found.get(origin)
            source = f"segment:{seg.name}"
            if candidate is None:
                found[origin] = OriginCandidate(origin, source)
            elif source not in candidate.source:
                candidate.source = f"{candidate.source},{source}"

        return list(found.values())

    def _score(self, candidate):
        """Score a candidate against the sampled offsets."""
        total = len(self.sample_offs)
        candidate.total = total
        if total == 0 or self.is_mapped is None:
            return candidate

        hits = 0
        code_hits = 0
        for off in self.sample_offs:
            ea = candidate.ea + off
            if self.is_mapped(ea):
                hits += 1
                if self.is_code is not None and self.is_code(ea):
                    code_hits += 1

        candidate.hits = hits
        candidate.code_hits = code_hits
        candidate.score = hits / total
        return candidate

    def _sorted_candidates(self):
        candidates = [self._score(c) for c in self.candidates()]
        candidates.sort(key=lambda c: c.sort_key, reverse=True)
        return candidates

    def _structural_evidence_is_overwhelming(self, best, candidates):
        """
        True when the offsets alone settle the question.

        Conditions, all of which must hold:

        * exactly one candidate survived scoring -- there is nothing else
          the offsets could plausibly mean,
        * every sampled offset landed inside the database, and
        * a meaningful number of those landed on *code*, which a wrong
          origin essentially never does.

        This exists so a renamed binary (``PerfectPiano`` in an IDB saved
        under some other name) does not stop to ask the user a question
        whose answer is already proven by 403/403 offsets mapping.
        """
        if len(candidates) != 1:
            return False
        if not self.sample_offs or self.is_mapped is None:
            return False
        if len(self.sample_offs) < MIN_TRUST_SAMPLES:
            return False
        if best.hits != best.total:
            return False
        return best.code_hits >= MIN_TRUST_CODE_HITS

    #-- resolution -------------------------------------------------------
    def resolve(self):
        """Resolve the module origin, prompting when the result is shaky."""
        candidates = self._sorted_candidates()

        if not candidates:
            return Resolution(None, None, [], False, "no-candidates", self.identity)

        best = candidates[0]
        runner_up = candidates[1] if len(candidates) > 1 else None

        ambiguous = False
        reason = "ok"

        if not self.sample_offs and len(candidates) > 1:
            # nothing to validate against: never guess between candidates
            ambiguous, reason = True, "unvalidated"

        elif self.sample_offs and self.is_mapped is None:
            # offsets were sampled but we cannot check them against the DB
            ambiguous, reason = (len(candidates) > 1), "unvalidated"

        else:
            if best.score < MIN_ACCEPT_SCORE:
                ambiguous, reason = True, "low-score"
            elif runner_up is not None and runner_up.score >= best.score * AMBIGUITY_RATIO:
                # both origins explain the trace: only a human can decide
                if runner_up.ea != best.ea:
                    ambiguous, reason = True, "tie"

        if (self.identity is not None and self.identity.match == MATCH_MISMATCH
                and not ambiguous):
            #
            # the trace was recorded from a different image than the one that
            # is open. that is worth saying out loud -- but it is only worth
            # *blocking* for when the offsets themselves are not already an
            # overwhelming answer (see the constants above)
            #
            if self._structural_evidence_is_overwhelming(best, candidates):
                reason = "image-mismatch-overridden"
            else:
                ambiguous = True
                reason = "image-mismatch"

        if not ambiguous:
            return Resolution(best.ea, best.source, candidates, False, reason,
                              self.identity)

        #
        # ambiguous: ask the user. Without a prompt (headless/tests) we
        # refuse to resolve rather than risk mapping every event wrongly.
        #
        if self.prompt is None:
            return Resolution(None, best.source, candidates, True, reason,
                              self.identity)

        chosen = self.prompt(candidates)
        if chosen is None:
            return Resolution(None, best.source, candidates, True, "cancelled",
                              self.identity)

        return Resolution(chosen.ea, chosen.source, candidates, True,
                          "confirmed", self.identity)
