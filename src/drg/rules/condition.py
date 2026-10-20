"""Parses a Sigma detection condition into something a check can reason about.

Two checks need more than the list of names a condition mentions.

The undefined selection check needs the names, so a typo in a condition is
caught before the rule reaches a backend that would match nothing in silence.

The unbounded selection check needs the structure, because a wildcard means
opposite things on either side of a negation. In ``selection and not 1 of
filter_*`` a wildcard inside ``filter_*`` excludes every event that has the
field populated, which narrows the rule. The same wildcard inside
``selection`` broadens it. A check that only collected names would call both
of those the same thing and be wrong half the time.

So the condition is parsed into a tree and evaluated. Asking whether one
selection is enough on its own to fire the rule is then a question of
evaluating the tree with that selection true and everything else false, which
is both shorter and more obviously correct than any set of rules about where
``not`` may appear.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from fnmatch import fnmatchcase

TOKEN = re.compile(
    r"""
      (?P<lparen>\()
    | (?P<rparen>\))
    | (?P<pipe>\|)
    | (?P<name>[A-Za-z0-9_*][A-Za-z0-9_*.-]*)
    | (?P<space>\s+)
    """,
    re.VERBOSE,
)

KEYWORDS = {"and", "or", "not", "of", "them", "all", "any"}


class ConditionError(Exception):
    """A condition this parser cannot read.

    Raised rather than guessed at. A guess would make a check either miss a
    real finding or invent one, and both are worse than a visible report that
    the condition could not be read, which is what the caller turns this into.
    """


class Node(ABC):
    """A parsed condition."""

    @abstractmethod
    def names(self) -> set[str]:
        """Every selection name or pattern the condition references."""

    @abstractmethod
    def evaluate(self, true_names: set[str], known: set[str]) -> bool:
        """Whether the condition holds when exactly ``true_names`` match.

        ``known`` is every selection the rule defines, which the quantifier
        forms need in order to expand a pattern or ``them``.
        """


@dataclass(frozen=True)
class Reference(Node):
    name: str

    def names(self) -> set[str]:
        return {self.name}

    def evaluate(self, true_names: set[str], known: set[str]) -> bool:
        if "*" in self.name:
            return any(fnmatchcase(candidate, self.name) for candidate in true_names)
        return self.name in true_names


@dataclass(frozen=True)
class Not(Node):
    operand: Node

    def names(self) -> set[str]:
        return self.operand.names()

    def evaluate(self, true_names: set[str], known: set[str]) -> bool:
        return not self.operand.evaluate(true_names, known)


@dataclass(frozen=True)
class And(Node):
    left: Node
    right: Node

    def names(self) -> set[str]:
        return self.left.names() | self.right.names()

    def evaluate(self, true_names: set[str], known: set[str]) -> bool:
        return self.left.evaluate(true_names, known) and self.right.evaluate(true_names, known)


@dataclass(frozen=True)
class Or(Node):
    left: Node
    right: Node

    def names(self) -> set[str]:
        return self.left.names() | self.right.names()

    def evaluate(self, true_names: set[str], known: set[str]) -> bool:
        return self.left.evaluate(true_names, known) or self.right.evaluate(true_names, known)


@dataclass(frozen=True)
class Quantifier(Node):
    """``1 of pattern``, ``all of them`` and the rest.

    ``pattern`` is None for the ``them`` form, which means every selection the
    rule defines.
    """

    mode: str  # "all" or "any"
    pattern: str | None

    def names(self) -> set[str]:
        return {self.pattern} if self.pattern else set()

    def _targets(self, known: set[str]) -> set[str]:
        if self.pattern is None:
            return set(known)
        return {name for name in known if fnmatchcase(name, self.pattern)}

    def evaluate(self, true_names: set[str], known: set[str]) -> bool:
        targets = self._targets(known)
        if not targets:
            # A pattern matching no selection is reported by the undefined
            # selection check. Treating it as unsatisfied here keeps one
            # problem from being reported twice in different words.
            return False
        if self.mode == "all":
            return targets <= true_names
        return bool(targets & true_names)


class _Parser:
    """Recursive descent over the token stream. not binds tighter than and,
    and and binds tighter than or, which is the precedence Sigma specifies."""

    def __init__(self, text: str) -> None:
        self.tokens = self._tokenize(text)
        self.position = 0

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        tokens: list[str] = []
        index = 0
        while index < len(text):
            match = TOKEN.match(text, index)
            if match is None:
                raise ConditionError(f"unexpected character {text[index]!r} at offset {index}")
            index = match.end()
            if match.lastgroup == "space":
                continue
            tokens.append(match.group())
        return tokens

    def _peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def _next(self) -> str:
        token = self._peek()
        if token is None:
            raise ConditionError("condition ended early")
        self.position += 1
        return token

    def parse(self) -> Node:
        node = self._parse_or()
        if self._peek() is not None:
            raise ConditionError(f"unexpected trailing token {self._peek()!r}")
        return node

    def _parse_or(self) -> Node:
        node = self._parse_and()
        while (token := self._peek()) is not None and token.lower() == "or":
            self._next()
            node = Or(node, self._parse_and())
        return node

    def _parse_and(self) -> Node:
        node = self._parse_not()
        while (token := self._peek()) is not None and token.lower() == "and":
            self._next()
            node = And(node, self._parse_not())
        return node

    def _parse_not(self) -> Node:
        token = self._peek()
        if token is not None and token.lower() == "not":
            self._next()
            return Not(self._parse_not())
        return self._parse_atom()

    def _parse_atom(self) -> Node:
        token = self._next()
        if token == "(":
            node = self._parse_or()
            if self._next() != ")":
                raise ConditionError("unbalanced parenthesis")
            return node
        lowered = token.lower()
        if lowered in {"1", "all", "any"}:
            return self._parse_quantifier(lowered)
        if lowered in KEYWORDS or token in {")", "|"}:
            raise ConditionError(f"expected a selection name, found {token!r}")
        return Reference(token)

    def _parse_quantifier(self, count: str) -> Node:
        token = self._next()
        if token.lower() != "of":
            raise ConditionError(f"expected 'of' after {count!r}, found {token!r}")
        target = self._next()
        if target.lower() == "them":
            return Quantifier("all" if count == "all" else "any", None)
        if target.lower() in KEYWORDS:
            raise ConditionError(f"expected a selection pattern, found {target!r}")
        return Quantifier("all" if count == "all" else "any", target)


def parse(condition: str) -> Node:
    """Parse one condition. Raises ConditionError if it cannot be read."""
    if not condition or not condition.strip():
        raise ConditionError("condition is empty")
    return _Parser(condition).parse()


def referenced_names(node: Node) -> set[str]:
    """Every selection name or pattern the condition mentions."""
    return node.names()


def is_solely_sufficient(node: Node, selection: str, known: set[str]) -> bool:
    """Whether ``selection`` matching is enough on its own to fire the rule.

    Evaluated with that one selection true and every other selection false,
    which is the state of an event that matches the selection and trips none of
    the rule's filters. If the condition holds there, then whatever that
    selection matches, the rule matches.
    """
    return node.evaluate({selection}, set(known))
