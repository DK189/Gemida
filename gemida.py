import os
import idaapi
import ida_hexrays
import ida_kernwin
from PyQt5 import QtWidgets, QtCore
from gemida.core import process_current_function, process_all_functions

API_KEY = os.getenv("GEMIDA_API_KEY")

def refresh_pseudocode():
    cur_view = ida_kernwin.get_current_viewer()
    if cur_view:
        vdui = ida_hexrays.get_widget_vdui(cur_view)
        if vdui:
            vdui.refresh_ctext()
            vdui.refresh_view(True)

class GemidaDialog(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(self.windowFlags() | QtCore.Qt.WindowStaysOnTopHint)
        self.setWindowTitle("Gemida - Gemini Assistant for IDA")
        self.setMinimumWidth(400)
        self.layout = QtWidgets.QVBoxLayout(self)

        self.info_label = QtWidgets.QLabel(
            "Gemida integrates Google Gemini AI into IDA Pro.\n"
            "Initial version: automatic analysis of functions."
        )
        self.layout.addWidget(self.info_label)

        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 0)  # infinite
        self.progress.setVisible(False)
        self.layout.addWidget(self.progress)

        self.analyze_current_btn = QtWidgets.QPushButton("Analyze current function")
        self.analyze_all_btn = QtWidgets.QPushButton("Analyze all functions")

        self.layout.addWidget(self.analyze_current_btn)
        self.layout.addWidget(self.analyze_all_btn)

        self.analyze_current_btn.clicked.connect(self._analyze_current)
        self.analyze_all_btn.clicked.connect(self._analyze_all)

    def _set_busy(self, busy: bool):
        # self.progress.setVisible(busy)
        self.analyze_current_btn.setEnabled(not busy)
        self.analyze_all_btn.setEnabled(not busy)

    def _analyze_current(self):
        self._set_busy(True)
        QtCore.QTimer.singleShot(1000, self._do_analyze_current)

    def _analyze_all(self):
        self._set_busy(True)
        QtCore.QTimer.singleShot(1000, self._do_analyze_all)

    def _do_analyze_current(self):
        try:
            self.hide()
            ida_kernwin.show_wait_box("HIDECANCEL\nGemida: Analyzing current function...")
            process_current_function()
        finally:
            self._set_busy(False)
            ida_kernwin.hide_wait_box()
            self.show()
            idaapi.msg("\n[Gemida] Analysis complete.\n")
            idaapi.refresh_idaview_anyway()
            refresh_pseudocode()

    def _do_analyze_all(self):
        try:
            self.hide()
            ida_kernwin.show_wait_box("HIDECANCEL\nGemida: Analyzing all functions...")
            process_all_functions()
        finally:
            self._set_busy(False)
            ida_kernwin.hide_wait_box()
            self.show()
            idaapi.msg("\n[Gemida] Analysis complete.\n")
            idaapi.refresh_idaview_anyway()
            refresh_pseudocode()


def show_gemida_form():

    global API_KEY
    API_KEY = os.getenv("GEMIDA_API_KEY")

    if API_KEY is None:
        idaapi.msg("[Gemida] Missing GEMIDA_API_KEY environment variable!\n")
        idaapi.info("Please set GEMIDA_API_KEY environment variable before using Gemida.")
        return

    if not hasattr(idaapi, "_gemida_dialog"):
        idaapi._gemida_dialog = GemidaDialog()
    idaapi._gemida_dialog.show()
    idaapi._gemida_dialog.raise_()


class gemida_plugmod_t(idaapi.plugmod_t):
    def run(self, arg):
        show_gemida_form()
        return 0


class gemida_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_MULTI
    comment = "Gemida - Gemini Assistant for IDA"
    help = "Gemida integrates Google Gemini AI into IDA Pro. Ctrl-Shift-G to open."
    wanted_name = "Gemida"
    wanted_hotkey = "Ctrl-Shift-G"

    def init(self):
        idaapi.msg("[Gemida] Plugin initialized. Press Ctrl-Shift-G to open Gemida window.\n")
        return gemida_plugmod_t()


def PLUGIN_ENTRY():
    return gemida_plugin_t()
