from dice.module import Module

from typing import Callable, Any, Generic, TypeVar

type EvaluatorWrapper = Callable[[Module], NoiseEvaluator]
type NoiseEvaluator = Callable[[Any], None]
type NoiseHandler = Callable[[Module], None]

T = TypeVar('T')

class NoiseGenericFactory(Generic[T]):
    def __init__(self, mod: Module):
        self.mod = mod
        self._cache: dict[str, T] = {}
        self._builders: dict[str, Callable] = {}
        self._default: T | None = None

    def build(self, name: str="") -> T | None:
        builder = self._builders.get(name, None)
        if not builder: 
            return self._default
        
        h = builder(self.mod)
        self._cache[name] = h
        return h

    def get(self, name: str) -> T | None:
        if name in self._cache:
            return self._cache[name]
        return self.build(name)
    
    def set_default(self, ev: T | None) -> 'NoiseGenericFactory':
        self._default = ev
        return self
    
    def supported(self) -> list[str]:
        return list(self._builders.keys())

class NoiseEvaluatorFactory(NoiseGenericFactory[NoiseEvaluator]):
    def add(self, name: str, ev: EvaluatorWrapper | NoiseEvaluator) -> 'NoiseEvaluatorFactory':
        match ev:
            case EvaluatorWrapper.__value__:
                self._builders[name] = lambda _: ev(self.mod)
            case NoiseEvaluator.__value__:
                self._builders[name] = lambda _: ev
        self._cache.pop(name, None)
        return self

class NoiseHandlerFactory(NoiseGenericFactory[NoiseHandler]):
    def add(self, name: str, h: NoiseHandler) -> 'NoiseHandlerFactory':
        self._builders[name] = lambda _: h(self.mod)
        self._cache.pop(name, None)
        return self
    
    def get_builders(self) -> list[str]:
        return list(self._builders.keys())

    def build_all(self) -> list[Callable]:
        r = []
        for n in self.get_builders():
            r.append(self.build(n))
        return r