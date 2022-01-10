from PyQt5.QtGui     import *
from PyQt5.QtCore    import *
from PyQt5.QtWidgets import *
from scapy.all import *
import sys, csv
import glob
import joblib

from DGA_Detector_thread import DGADetectorThread
from DGA_Detector_misc import *

class DGADetector(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DGA Detector")
        self.width = 850
        self.height = 950
        self.setMinimumSize(self.width, self.height)
        self.autoscroll = True
        self.tableStyleSheet = "::section{Background-color: rgb(177, 181, 180)}"
        
        self.domainFeatures = []
        self.domainClassifierPreds = []
        self.domainClassifierProbs = []
        self.domainClusterPreds = []
        
        classifierList = glob.glob('../Models/*_clf.joblib')
        clusterList = glob.glob('../Models/*_clt.joblib')
        
        self.classifiers = [joblib.load(clf) for clf in classifierList]
        self.clusterers = [joblib.load(clt) for clt in clusterList]
        
        self.widget = QWidget(self)
        self.layout = QGridLayout()
        self.widget.setLayout(self.layout)
        
        self._createMenuBar()
        self._createTable(["No.", "Domain Name", "IP", "Category"])
        self._createClassifierTable(["Classifier", "Prediction", "Confidence"], classifierList)
        self._createClusterTable(["Clustering Algo", "Prediction", "Confidence"], clusterList)
        self._createAttributeTable(["Domain", "Length", "Rel Entropy", "Num Percent", "MCC", "MCV", "Vowel Count", "Vowel Rate"])
        #self.setLayout(self.layout)
        
        self.clfWidget = QWidget(self)
        self.clfLayout = QGridLayout()
        self.clfWidget.setLayout(self.clfLayout)
        
        self.clfLayout.addWidget(self.classifierTable, 0, 0, 1, 2)

        self.clfResultLabel = QLabel("Majority Voting Ensemble:")
        self.clfResult = QLineEdit()
        self.clfResult.setReadOnly(True)
        self.clfResult.setMinimumHeight(30)
        
        self.clfLayout.addWidget(self.clfResultLabel, 1, 0)
        self.clfLayout.addWidget(self.clfResult, 1, 1)
        
        self.cltWidget = QWidget(self)
        self.cltLayout = QGridLayout()
        self.cltWidget.setLayout(self.cltLayout)
        
        self.cltLayout.addWidget(self.clusterTable, 0, 0, 1, 2)
        
        self.cltResultLabel = QLabel("DGA Family:")
        self.cltResult = QLineEdit()
        self.cltResult.setReadOnly(True)
        self.cltResult.setMinimumHeight(30)
        self.cltLayout.addWidget(self.cltResultLabel, 1, 0)
        self.cltLayout.addWidget(self.cltResult, 1, 1)
        
        self.layout.addWidget(self.tableWidget,0, 0, 1, 2)
        self.layout.addWidget(self.attributeTable, 1, 0, 1, 2)
        self.layout.addWidget(self.clfWidget, 2, 0)
        self.layout.addWidget(self.cltWidget, 2, 1)
        
        self.setCentralWidget(self.widget)
            
    def _createTable(self, headers):
        self.tableWidget = QTableWidget()
        self.tableWidget.setStyleSheet('border-bottom: 1px solid #d6d9dc')
        self.tableWidget.setTabKeyNavigation(False)
        self.tableWidget.setProperty("showDropIndicator", False)
        self.tableWidget.setDragDropOverwriteMode(False)
        self.tableWidget.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tableWidget.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tableWidget.setShowGrid(True)
        self.tableWidget.setGridStyle(Qt.NoPen)
        self.tableWidget.setRowCount(0)
        self.tableWidget.setColumnCount(len(headers))
        self.tableWidget.setHorizontalHeaderLabels(headers)
        self.tableWidget.horizontalHeader().setVisible(True)
        self.tableWidget.horizontalHeader().setCascadingSectionResizes(True)
        self.tableWidget.horizontalHeader().setHighlightSections(False)
        self.tableWidget.horizontalHeader().setSortIndicatorShown(True)
        self.tableWidget.verticalHeader().setVisible(False)
        self.tableWidget.setSortingEnabled(False)
        self.tableWidget.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tableWidget.setAutoScroll(True)
        self.tableWidget.setFixedHeight(500)
        self.tableWidget.horizontalHeader().setStyleSheet(self.tableStyleSheet)
        
        self.tableWidget.horizontalHeader(). setSectionResizeMode(QHeaderView.Stretch)
        sizePolicy = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.tableWidget.sizePolicy().hasHeightForWidth())
        self.tableWidget.setSizePolicy(sizePolicy)
        
        self.tableWidget.clicked.connect(self.showDomainResults)
        
    def _createClassifierTable(self, headers, classifierList):
        self.classifierTable = QTableWidget()
        self.classifierTable.setColumnCount(len(headers))
        self.classifierTable.setHorizontalHeaderLabels(headers)
        self.classifierTable.verticalHeader().setVisible(False)
        self.classifierTable.setTabKeyNavigation(False)
        self.classifierTable.setProperty("showDropIndicator", False)
        self.classifierTable.setDragDropOverwriteMode(False)
        self.classifierTable.setSortingEnabled(False)
        self.classifierTable.setEditTriggers(QTableWidget.NoEditTriggers)
        self.classifierTable.setSelectionMode(QAbstractItemView.NoSelection)
        self.classifierTable.horizontalHeader().setStyleSheet(self.tableStyleSheet)
        
        self.classifierTable.horizontalHeader(). setSectionResizeMode(QHeaderView.Stretch)
        sizePolicy = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.classifierTable.sizePolicy().hasHeightForWidth())
        self.classifierTable.setSizePolicy(sizePolicy)
        
        for row, classifierPath in enumerate(classifierList):
            rowpos = self.classifierTable.rowCount()
            self.classifierTable.insertRow(rowpos)
            self.classifierTable.setItem(rowpos, 0, QTableWidgetItem(str(os.path.basename(classifierPath).split("_clf")[0])))
 
    def _createClusterTable(self, headers, clusterList):
        self.clusterTable = QTableWidget()
        self.clusterTable.setColumnCount(len(headers))
        self.clusterTable.setHorizontalHeaderLabels(headers)
        self.clusterTable.verticalHeader().setVisible(False)
        self.clusterTable.setTabKeyNavigation(False)
        self.clusterTable.setProperty("showDropIndicator", False)
        self.clusterTable.setDragDropOverwriteMode(False)
        self.clusterTable.setSortingEnabled(False)
        self.clusterTable.setEditTriggers(QTableWidget.NoEditTriggers)
        self.clusterTable.setSelectionMode(QAbstractItemView.NoSelection)
        self.clusterTable.horizontalHeader().setStyleSheet(self.tableStyleSheet)
        
        self.clusterTable.horizontalHeader(). setSectionResizeMode(QHeaderView.Stretch)
        sizePolicy = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.clusterTable.sizePolicy().hasHeightForWidth())
        self.clusterTable.setSizePolicy(sizePolicy)
        

        for row, clusterPath in enumerate(clusterList):
            rowpos = self.clusterTable.rowCount()
            self.clusterTable.insertRow(rowpos)
            self.clusterTable.setItem(rowpos, 0, QTableWidgetItem(str(os.path.basename(clusterPath).split("_clt")[0])))
    
    def _createAttributeTable(self, headers):
        self.attributeTable = QTableWidget()
        self.attributeTable.setColumnCount(len(headers))
        self.attributeTable.setHorizontalHeaderLabels(headers)
        self.attributeTable.verticalHeader().setVisible(False)
        self.attributeTable.setTabKeyNavigation(False)
        self.attributeTable.setProperty("showDropIndicator", False)
        self.attributeTable.setDragDropOverwriteMode(False)
        self.attributeTable.setSortingEnabled(False)
        self.attributeTable.setEditTriggers(QTableWidget.NoEditTriggers)
        self.attributeTable.setSelectionMode(QAbstractItemView.NoSelection)
        self.attributeTable.setFixedHeight(70)
        self.attributeTable.horizontalHeader().setStyleSheet(self.tableStyleSheet)
        
        self.attributeTable.horizontalHeader(). setSectionResizeMode(QHeaderView.Stretch)
        sizePolicy = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.attributeTable.sizePolicy().hasHeightForWidth())
        self.attributeTable.setSizePolicy(sizePolicy)
        
        rowpos = self.attributeTable.rowCount()
        self.attributeTable.insertRow(rowpos)
        
    def _createMenuBar(self):
        self.menubar = QMenuBar(self)
        self.setMenuBar(self.menubar)
        self.menubar.setStyleSheet('font-size: 11pt')
        
        self.actionStart = QAction('Start', self)
        self.actionStart.triggered.connect(self.packetSniff)
        self.menubar.addAction(self.actionStart)
        
        self.actionStop = QAction('Stop', self)
        self.menubar.addAction(self.actionStop)
        
        self.actionClear = QAction('Clear', self)
        self.actionClear.triggered.connect(self.packetClear)
        self.menubar.addAction(self.actionClear) 
        
        self.actionSaveCSV = QAction('Save as CSV', self)
        self.actionSaveCSV.triggered.connect(self.savePacketsCSV)
        
        self.actionSavePCAP = QAction('Save as pcap', self)
        self.actionSavePCAP.triggered.connect(self.savePacketsPCAP)
        
        self.actionSaveDGA = QAction('Log Malicious Domains', self)
        self.actionSaveDGA.triggered.connect(self.savePacketsDGA)
        
        self.saveMenu = QMenu('Save', self)
        self.saveMenu.addAction(self.actionSaveCSV)
        self.saveMenu.addAction(self.actionSavePCAP)
        self.saveMenu.addAction(self.actionSaveDGA)
        self.menubar.addMenu(self.saveMenu)
        
        self.actionScroll = QAction('Disable Auto Scroll', self)
        self.actionScroll.triggered.connect(self.autoScrollSet)
        self.actionScroll.setCheckable(True)
        self.actionScroll.setChecked(True)
        
        self.menubar.addAction(self.actionScroll) 
        
    def autoScrollSet(self):
        if (self.actionScroll.isChecked() == True):
            self.tableWidget.scrollToBottom()
            self.actionScroll.setText('Disable Auto Scroll')
        if (self.actionScroll.isChecked() == False):
            self.actionScroll.setText('Enable Auto Scroll')     
    
    def packetSniff(self):     
        self.actionStart.setEnabled(False)
        self.actionStop.setEnabled(True)
        self.actionClear.setEnabled(True)
        
        self.thread = QThread()
        self.worker = DGADetectorThread(classifiers=self.classifiers, clusterers=self.clusterers)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.startSniff)
        self.actionStop.triggered.connect(self.worker.endSniff)
        
        self.worker.packetData.connect(self.addPacketToTableWidget)
        self.worker.quitBool.connect(self.stopSniff)
        self.thread.start()
    
    quitBool = pyqtSignal()
    def stopSniff(self, quitBool):
        if(quitBool == 1):
            self.thread.quit()
            self.actionStart.setEnabled(True)
            self.actionStop.setEnabled(False)

    packetData = pyqtSignal()
    def addPacketToTableWidget(self, packetData):
        tableData = packetData[0]
        rowpos = self.tableWidget.rowCount()
        self.tableWidget.insertRow(rowpos)
        self.tableWidget.setItem(rowpos, 0, QTableWidgetItem(str(rowpos+1)))
        #self.tableWidget.setItem(rowpos, 1, QTableWidgetItem(str(tableData['timestamp'])))
        self.tableWidget.setItem(rowpos, 1, QTableWidgetItem(str(tableData['domain_name'])))
        self.tableWidget.setItem(rowpos, 2, QTableWidgetItem(str(tableData['domain_ip'])))
        self.tableWidget.setItem(rowpos, 3, QTableWidgetItem(tableData['category']))
        self.setColortoRow(self.tableWidget, rowpos, tableData['row_color'])
        
        self.domainFeatures.append(packetData[1])
        self.domainClassifierPreds.append(packetData[2])
        self.domainClassifierProbs.append(packetData[3])
        self.domainClusterPreds.append(packetData[4])
        
        self.vbar = self.tableWidget.verticalScrollBar()
        self._scroll = self.vbar.value() == self.vbar.maximum()
        
        if self._scroll and self.actionScroll.isChecked():
            self.tableWidget.scrollToBottom()
            
    def setColortoRow(self, table, rowIndex, color):
        for j in range(table.columnCount()):
            table.item(rowIndex, j).setBackground(color)
            
    def packetClear(self):
        if hasattr(self.thread, 'quit'):
            self.thread.quit()
        self.tableWidget.clearContents()
        self.tableWidget.setRowCount(0)
        self.domainFeatures = []
        self.domainClassifierPreds = []
        self.domainClusterPreds = []
        self.domainClusterPreds = []
        
    def savePacketsPCAP(self):
        path = QFileDialog.getSaveFileName(self, 'Save File', '', 'pcap(*.pcap)')
        if path[0] is not '':
            path = str(path[0])
            wrpcap(path, self.worker.packetList)
    
    def savePacketsDGA(self):
        path = QFileDialog.getSaveFileName(self, 'Save File', '', 'pcap(*.pcap)')
        if path[0] is not '':
            path = str(path[0])
            wrpcap(path, self.worker.blackListAccess)
    
    def savePacketsCSV(self):
        path = QFileDialog.getSaveFileName(self, 'Save File', '', 'CSV(*.csv)')
        if path[0] is not '':
            with open(path[0], 'w') as stream:
                writer = csv.writer(stream, lineterminator='\n')
                for row in range(self.tableWidget.rowCount()):
                    rowdata = []
                    for column in range(self.tableWidget.columnCount()):
                        item = self.tableWidget.item(row, column)
                        if item is not None:
                            rowdata.append(item.text())
                        else:
                            rowdata.append('')

                    writer.writerow(rowdata)
    
    def showDomainResults(self):
        domain_row = self.tableWidget.selectedItems() 
        idx = int(domain_row[0].text()) - 1
        
        self.attributeTable.setItem(0, 0, QTableWidgetItem(remove_tlds(domain_row[1].text())))
        self.attributeTable.setItem(0, 1, QTableWidgetItem(str(self.domainFeatures[idx][0])))
        self.attributeTable.setItem(0, 2, QTableWidgetItem(str(round(self.domainFeatures[idx][1], 4))))
        self.attributeTable.setItem(0, 3, QTableWidgetItem(str(round(self.domainFeatures[idx][2], 4))))
        self.attributeTable.setItem(0, 4, QTableWidgetItem(str(round(self.domainFeatures[idx][3], 4))))
        self.attributeTable.setItem(0, 5, QTableWidgetItem(str(round(self.domainFeatures[idx][4], 4))))
        self.attributeTable.setItem(0, 6, QTableWidgetItem(str(round(self.domainFeatures[idx][5], 4))))
        self.attributeTable.setItem(0, 7, QTableWidgetItem(str(round(self.domainFeatures[idx][6], 4))))
        
        self.showClassifierResults(idx)
        
    def showClassifierResults(self, idx):
        for i, pred in enumerate(self.domainClassifierPreds[idx]):
            self.classifierTable.setItem(i, 2, QTableWidgetItem(str(round(self.domainClassifierProbs[idx][i], 4))))
            if pred == 0:
                self.classifierTable.setItem(i, 1, QTableWidgetItem("Malicious"))
            else:
                self.classifierTable.setItem(i, 1, QTableWidgetItem("Benign"))
        
        if(max(self.domainClassifierPreds[idx], key=self.domainClassifierPreds[idx].count) == 0):
            self.clfResult.setText("Malicious")
        else:
            self.clfResult.setText("Benign")
    def showClusterResults(self):
        pass
    
def main():
    app = QApplication(sys.argv)
    dgadetector = DGADetector()
    dgadetector.show()
    app.exec()
    
if __name__ == "__main__":
    main()
    
