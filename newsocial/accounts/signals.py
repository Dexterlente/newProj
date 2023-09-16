from django.dispatch import Signal


class CustomSignal(Signal):
    pass


register_signal = Signal()
