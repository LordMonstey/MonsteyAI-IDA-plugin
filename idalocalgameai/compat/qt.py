"""Qt compatibility for IDA 9.0 first, with a future PySide6 path."""

try:
    from PyQt5 import QtCore, QtGui, QtWidgets

    QT_BINDING = "PyQt5"
except ImportError:
    try:
        from PySide6 import QtCore, QtGui, QtWidgets

        QT_BINDING = "PySide6"
    except ImportError as exc:
        raise ImportError("MonsteyAI-IDA-plugin requires PyQt5 in IDA 9.0 or PySide6 in newer IDA builds") from exc


def signal(*args, **kwargs):
    if QT_BINDING == "PyQt5":
        return QtCore.pyqtSignal(*args, **kwargs)
    return QtCore.Signal(*args, **kwargs)


def slot(*args, **kwargs):
    if QT_BINDING == "PyQt5":
        return QtCore.pyqtSlot(*args, **kwargs)
    return QtCore.Slot(*args, **kwargs)
