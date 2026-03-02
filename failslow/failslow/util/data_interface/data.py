from abc import ABC, abstractmethod


class Data(ABC):
    @abstractmethod
    def get_data(self):
        raise NotImplementedError()

class InterativeData(Data):
    @abstractmethod
    def __iter__(self):
        raise NotImplementedError()


__all__ = ["Data", "InterativeData"]