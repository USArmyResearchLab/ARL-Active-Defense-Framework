#!/usr/bin/env python3
import sys
import os

from PyQt5.QtWidgets import QApplication, QMainWindow, QSizePolicy, QMessageBox, QPushButton, QFileDialog, QInputDialog
from PyQt5.QtCore import pyqtSlot
from PyQt5 import QtCore

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt

import paho.mqtt.client as mqtt
import time

dataLimit = 500


class MqttClient(QtCore.QObject):
    TOPIC = 'VisToSim'
    client = None

    def __init__(self, parent, ip='localhost', topic=None):
        super(MqttClient, self).__init__(parent)
        self.parent = parent
        self.ip = ip
        if topic:
            self.TOPIC = topic

        timestamp = time.time()
        self.client = mqtt.Client('Plot'+str(timestamp))

        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message

        self.client.connect(ip, 1883, 60)
        self.client.loop_start()

    # The callback for when the client receives a CONNACK response from the server.

    def on_connect(self, client, userdata, flags, rc):
        print("Connected to %s with result code %s" % (self.ip, rc))

        # Subscribing in on_connect() means that if we lose the connection and
        # reconnect then subscriptions will be renewed.
        # subscribe to messages
        self.subscribe(self.TOPIC)

    # The callback for when a PUBLISH message is received from the server.
    def on_message(self, client, userdata, msg):
        #logging.debug("topic %s, msg: %s", msg.topic, msg.payload)
        #print ("topic %s, msg: %s", msg.topic, msg.payload)
        self.parent.updateData(msg.payload.decode('utf-8'))

    def subscribe(self, topic):
        self.client.subscribe(topic)
        print('subscribe %s' % topic)

    def unsubscribe(self, topic):
        self.client.unsubscribe(topic)
        print('unsubscribe %s' % topic)


def getSPNInfo(spn):
    return spn, '', 0.0, 0.0


class App(QMainWindow):
    client = None
    xdata = []
    ydata = []
    csvxdata = []
    csvydata = []
    resized = QtCore.pyqtSignal()

    def __init__(self, *args):
        super().__init__()
        self.left = 10
        self.top = 10
        self.title = 'Data Plot'
        self.width = 1200  # 640
        self.height = 600  # 400
        App.client = MqttClient(self, *args)
        self.offset = 0
        self.resolution = 0
        self.params = set()
        self.isPaused = False
        self.start = False
        self.selectedSPN = None
        self.useOffset = False
        self.starttime = -1
        self.title = ''
        self.units = ''
        self.csvFileName = None
        self.initUI()

    def initUI(self):
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)

        # width=11.5, height=6) #width=5, height=4)
        self.m = PlotCanvas(self,  width=11, height=6)
        self.m.move(0, 0)

        self.button1 = QPushButton('', self)
        self.button1.setToolTip('Select a param to plot')
        self.button1.move(self.width-100, 0)
        self.button1.resize(100, 100)
        self.button1.clicked.connect(self.selectParam)

        self.button2 = QPushButton('Save\nPlot', self)
        self.button2.setToolTip('Save plot to file')
        self.button2.move(self.width-100, 100)
        self.button2.resize(100, 50)
        self.button2.clicked.connect(self.save_plot)

        self.button3 = QPushButton('Load\nCSV', self)
        self.button3.setToolTip('Load data from CSV')
        self.button3.move(self.width-100, 150)
        self.button3.resize(100, 50)
        self.button3.clicked.connect(self.load_csv)

        self.pauseButton = QPushButton('', self)
        self.pauseButton.setToolTip('Pause/Unpause live-plot of MQTT')
        self.pauseButton.move(self.width-100, 200)
        self.pauseButton.resize(100, 100)
        self.pauseButton.clicked.connect(self.on_pause)
        self.resetPlot(None)

        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.timerEvent)
        self.show()
        self.timer.start(500)

    @pyqtSlot()
    def save_plot(self):
        print('save')
        self.m.saveFigure()

    def load_csv(self):
        print('file open')
        self.openFileNameDialog()

    def on_pause(self):
        if self.isPaused == True:
            self.isPaused = False
            self.pauseButton.setText('Pause')
        else:
            self.isPaused = True
            self.pauseButton.setText('Resume')

    def resetPlot(self, spn):
        print('plotting', spn)
        self.isPaused = True  # stop updates
        self.m.clearPlot()
        name, units, offset, resolution = getSPNInfo(spn)
        self.title = name
        self.units = units
        self.m.setLabels(self.title, self.units)
        self.offset = offset
        self.resolution = resolution
        self.selectedSPN = spn
        self.title = name
        self.units = units
        self.xdata.clear()
        self.ydata.clear()
        self.csvxdata.clear()
        self.csvydata.clear()
        # load CSV to get params or data
        if self.csvFileName:
            self.getCSVData(self.csvFileName)
        if spn:  # unpause if param valid
            self.on_pause()
            self.pauseButton.setDisabled(False)
        else:  # disable button
            self.pauseButton.setDisabled(True)
            self.pauseButton.setText('')

    def getCSVData(self, fileName):
        print('reading', fileName)
        with open(fileName, 'r') as file:
            while True:
                entry = file.readline().strip()
                if not entry:
                    break
                ts, name, val = entry.split(',', 2)
                # populate the spns list from the incoming messages
                self.params.add(name)
                if name == self.selectedSPN:
                    ts = float(ts)
                    val = float(val)
                    self.csvxdata.append(ts)
                    self.csvydata.append(val)

    def openFileNameDialog(self):
        self.csvFileName = None
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getOpenFileName(
            self, "QFileDialog.getOpenFileName()", "", "All Files (*);;Python Files (*.csv)", options=options)
        if fileName:
            self.csvFileName = fileName
        self.resetPlot(None)  # reset plot to clear CSV or get SPNs/display CSV
        self.timerEvent()

    def updateData(self, data):
        ts, name, val = data.split(',')
        # populate the spns list from the incoming messages
        self.params.add(name)
        if name == self.selectedSPN:
            if self.starttime == -1:
                self.starttime = float(ts)

            sec = float(ts) - self.starttime
            x, y = sec, float(val)

            self.xdata.append(x)
            value = y
            self.ydata.append(value)

    def timerEvent(self):
        self.button1.setText('Select Param\n(%s)' % len(self.params))
        if not self.isPaused:
            self.m.plotData(self.xdata, self.ydata,
                            self.csvxdata, self.csvydata)

    def selectParam(self):
        self.resetPlot(None)
        items = sorted(self.params)
        item, ok = QInputDialog.getItem(self, "select Param dialog",
                                        "list of Params", items, 0, False)
        if ok and item:
            self.resetPlot(item)


class PlotCanvas(FigureCanvas):

    min_x = 0
    max_x = 100

    def __init__(self, parent=None, width=5, height=4, dpi=100):
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

    def plotData(self, set1, set2, altset1=None, altset2=None):
        # self.axes.cla() # clears plot
        data = [set1, set2]

        self.axes.relim()
        self.axes.autoscale_view()
        self.axes.plot(set1, set2, 'r-')
        if altset1 and altset2:
            self.axes.plot(altset1, altset2, 'b-')
        self.draw()
        self.flush_events()

    def saveFigure(self):
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
