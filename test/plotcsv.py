#!/usr/bin/env python3
import sys
import os

from PyQt5.QtWidgets import QApplication, QMainWindow, QSizePolicy, QMessageBox, QPushButton, QFileDialog, QInputDialog
from PyQt5.QtCore import pyqtSlot
from PyQt5 import QtCore

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from matplotlib import scale
import matplotlib.pyplot as plt

import time
import csv

dataLimit = 500


def getSPNInfo(spn):
    return spn, '', 0.0, 0.0


class App(QMainWindow):
    client = None
    TS_FIELD = 'ts'
    REL_TS = False
    resized = QtCore.pyqtSignal()

    def parse_args(self, args):
        for arg in args:
            try:
                k, v = arg.split('=', 1)
                if k == 'clamp':
                    self.clamp = float(v)
                if k == 'units':
                    self.units = v
                if k == 'title':
                    self.title_arg = v
                if k == 'ts':
                    self.TS_FIELD = v
                if k == 'rel':
                    self.REL_TS = int(v)
                if k == 'start':
                    self.start_ts = float(v)
                if k == 'end':
                    self.end_ts = float(v)
                if k == 'param':
                    self.params.add(v)
                    self.param_arg = v
                if k == 'fmt':
                    self.fmt = v.split(',')
                if k == 'pdf':
                    self.save_arg = v
                if k == 'yscale':
                    self.yscale = v
            except:
                self.CSVFileNames.append(arg)

    def __init__(self, *args):
        super().__init__()
        self.left = 10
        self.top = 10
        self.title = 'Data Plot'
        self.width = 1200  # 640
        self.height = 600  # 400
        self.offset = 0
        self.resolution = 0
        self.params = set()
        self.isPaused = False
        self.start = False
        self.selectedParam = None
        self.useOffset = False
        self.starttime = -1
        self.title = ''
        self.units = ''
        self.yscale = 'linear'
        self.clamp = self.start_ts = self.end_ts = None
        self.CSVFileNames = []
        self.title_arg = self.param_arg = self.fmt = self.save_arg = None
        self.parse_args(args)
        self.initUI()

    def initUI(self):
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)

        # width=11.5, height=6) #width=5, height=4)
        self.m = PlotCanvas(self,  width=11, height=6, fmt=self.fmt)
        self.m.move(0, 0)

        self.button1 = QPushButton('Select Param', self)
        self.button1.setToolTip('Select a param to plot')
        self.button1.move(self.width-100, 0)
        self.button1.resize(100, 100)
        self.button1.clicked.connect(self.selectParam)

        self.button2 = QPushButton('Save\nPlot', self)
        self.button2.setToolTip('Save plot to file')
        self.button2.move(self.width-100, 150)
        self.button2.resize(100, 50)
        self.button2.clicked.connect(self.save_plot)

        self.button3 = QPushButton('Add\nCSV', self)
        self.button3.setToolTip('Add data from CSV')
        self.button3.move(self.width-100, 100)
        self.button3.resize(100, 50)
        self.button3.clicked.connect(self.load_csv)

        self.button4 = QPushButton('Clear\nAll', self)
        self.button4.setToolTip('Clear all data and load initial CSV')
        self.button4.move(self.width-100, 200)
        self.button4.resize(100, 50)
        self.button4.clicked.connect(self.reset)

        self.show()
        if not self.CSVFileNames:
            self.load_csv()
        else:
            self.resetPlot(self.param_arg)
        if self.save_arg:
            self.m.saveFigure(self.save_arg)
            sys.exit()

    @pyqtSlot()
    def save_plot(self):
        print('save')
        self.m.saveFigure()

    def load_csv(self):
        print('file open')
        self.openFileNameDialog()
        if self.CSVFileNames:
            self.resetPlot(self.selectedParam)
        if not self.selectedParam:
            self.selectParam()

    def reset(self):
        print('reset')
        self.CSVFileNames = []
        self.params = set()
        self.resetPlot()
        self.load_csv()

    def resetPlot(self, param=None):
        if param:
            print(param)
            self.button1.setText(param+'\n(click to change)')
        self.m.clearPlot()
        self.data = []
        self.selectedParam = param
        self.getCSVData()

    def getCSVData(self):
        for fileName in self.CSVFileNames:
            print('reading', fileName)
            with open(fileName, 'r') as file:
                reader = csv.DictReader(file)
                self.params.update(
                    r for r in reader.fieldnames if r != self.TS_FIELD)
                print('%s: %s params' % (fileName, len(self.params)))
                if self.selectedParam:
                    selectedParams = self.selectedParam.split(',')
                    xd = list()
                    yds = list()
                    for _ in range(len(selectedParams)):
                        yds.append(list())
                    init_ts = None
                    for d in reader:
                        if self.TS_FIELD in d and all(p in d for p in selectedParams):
                            ts = float(d[self.TS_FIELD])
                            if init_ts is None:
                                init_ts = ts
                                print('%s: init %s rel %s start %s end %s' % (
                                    fileName, init_ts, self.REL_TS, self.start_ts, self.end_ts))
                            if self.REL_TS:
                                ts -= init_ts
                            if self.start_ts and ts < self.start_ts:
                                continue
                            if self.end_ts and ts > self.end_ts:
                                continue
                            xd.append(ts)
                            for i, p in enumerate(selectedParams):
                                val = float(d[p])
                                if self.clamp:
                                    val = min(val, self.clamp)
                                yds[i].append(val)
                    for yd in yds:
                        self.data.append((xd, yd))
                    print('%s: %s datapoints for %s' %
                          (fileName, len(xd), selectedParams))
        if self.selectedParam:
            self.plotCSVData()

    def plotCSVData(self):
        self.m.clearPlot()
        if self.title_arg:
            self.title = self.title_arg
        else:
            self.title = self.selectedParam
        self.m.setLabels(self.title, self.units)
        self.m.plotData(*self.data, yscale=self.yscale)

    def openFileNameDialog(self):
        self.csvFileName = None
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getOpenFileName(
            self, "QFileDialog.getOpenFileName()", "", "All Files (*);;Python Files (*.csv)", options=options)
        if fileName:
            self.CSVFileNames.append(fileName)

    def selectParam(self):
        items = sorted(self.params)
        item, ok = QInputDialog.getItem(self, "select Param dialog",
                                        "list of Params", items, 0, False)
        if ok and item:
            self.resetPlot(item)


class PlotCanvas(FigureCanvas):

    min_x = 0
    max_x = 100

    fmt = ('b-', 'r-', 'g-')

    def __init__(self, parent=None, width=5, height=4, dpi=100, fmt=None):
        if fmt:
            self.fmt = fmt
        fig = Figure(figsize=(width, height), dpi=dpi)
        self.axes = fig.add_subplot(111)
        # Autoscale on unknown axis and known lims on the other
        # self.axes.set_autoscaley_on(True)
        #self.axes.set_xlim(self.min_x, self.max_x)
        # Other stuff
        self.axes.grid()

        FigureCanvas.__init__(self, fig)
        self.setParent(parent)

        FigureCanvas.setSizePolicy(self,
                                   QSizePolicy.Expanding,
                                   QSizePolicy.Expanding)
        FigureCanvas.updateGeometry(self)

    def setLabels(self, title, ylabel):
        self.axes.set_title(title)
        self.axes.set_xlabel('Time(s)')
        self.axes.set_ylabel('\n'+ylabel)
        self.draw()

    def clearPlot(self):
        self.axes.cla()  # clears plot
        self.draw()
        self.flush_events()

    def plotData(self, *data, yscale='linear'):
        for i, d in enumerate(data):
            set1, set2 = d
            self.axes.set_yscale(yscale)
            self.axes.relim()
            self.axes.autoscale_view()
            self.axes.plot(set1, set2, self.fmt[i % len(self.fmt)])
            self.draw()
            self.flush_events()

    def saveFigure(self, fileName):
        if not fileName:
            options = QFileDialog.Options()
            options |= QFileDialog.DontUseNativeDialog
            fileName, _ = QFileDialog.getSaveFileName(
                self, "QFileDialog.getSaveFileName()", "", "All Files (*);;Text Files (*.pdf)", options=options)
        if fileName:
            print(fileName)
            self.figure.savefig(fileName)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App(*sys.argv[1:])
    sys.exit(app.exec_())
