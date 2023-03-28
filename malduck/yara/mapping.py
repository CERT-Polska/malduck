from collections import defaultdict
from typing import (
    Callable,
    ItemsView,
    Iterator,
    KeysView,
    Mapping,
    Sequence,
    TypeVar,
    Union,
    ValuesView,
)

T = TypeVar("T")


def aggregate(
    collection: Sequence[T], keyfunc: Callable[[T], Sequence[str]]
) -> Mapping[str, Sequence[T]]:
    """
    Aggregates elements into {identifier: [elements...]} dictionary.

    keyfunc returns list of identifiers where element should be added
    """
    mapping = defaultdict(list)
    for el in collection:
        for key in keyfunc(el):
            mapping[key].append(el)
    return dict(mapping)


V = TypeVar("V")
D = TypeVar("D")


class UserMapping(Mapping[str, V]):
    """
    Behaves similarly to frozen dict with predefined default for "get"

    Supports getting items via getattr for compatibility with older modules
    """

    def __init__(self, elements: Mapping[str, V], default=None) -> None:
        self.elements = elements
        self.default = default

    def keys(self) -> KeysView[str]:
        """List of matched string identifiers"""
        return self.elements.keys()

    def items(self) -> ItemsView[str, V]:
        return self.elements.items()

    def values(self) -> ValuesView[V]:
        return self.elements.values()

    def get(self, item: str, default: Union[V, D] = None) -> Union[V, D]:
        """Get matched string offsets or default if not matched"""
        if default is None:
            default = self.default
        return self.elements.get(item, default)

    def __bool__(self) -> bool:
        return bool(self.elements)

    def __nonzero__(self) -> bool:
        return self.__bool__()

    def __contains__(self, item: object) -> bool:
        return item in self.elements

    def __getitem__(self, item: str) -> V:
        return self.elements[item]

    def __getattr__(self, item: str) -> V:
        try:
            return self[item]
        except IndexError:
            raise AttributeError()

    def __iter__(self) -> Iterator[str]:
        return iter(self.elements)

    def __len__(self) -> int:
        return len(self.elements)
