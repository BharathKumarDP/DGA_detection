from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from scapy.all import *
from joblib import load

from DGA_Detector_misc import *

class DGADetectorThread(QObject):
    def __init__(self, classifiers, clusterers, parent=None):
        QObject.__init__(self, parent=parent)
        self.packetList = []
        self.end = False
        self.encoding = 'utf-8'
        self.classifiers = classifiers
        self.clusterers = clusterers
        
    quitBool = pyqtSignal(int)
    def endSniff(self):
        QApplication.processEvents()
        self.end = True
        self.quitBool.emit(1)
        
    def sniffStatus(self):
        QApplication.processEvents()
        return self.end 
    
    packetData = pyqtSignal(tuple)
    def handlePacket(self, packet):
        self.packetList.append(packet)
        QApplication.processEvents()
        #print(packet.getlayer("DNS").summary())
        #print(repr(packet[DNS]))

        tableViewPart = dict()
        tableViewPart['timestamp'] = packet.time
        tableViewPart['domain_name'] = packet[DNS].qd.qname.decode()
        
        if packet.haslayer(DNSRR):
            tableViewPart['domain_ip'] = str(packet[DNS][DNSRR].rdata)
        else:
            tableViewPart['domain_ip'] = '' 
        
        domain_feature = create_feature_vector(remove_tlds(str(tableViewPart['domain_name'])))
        
        classifier_preds = [classifier.predict([domain_feature])[0] for classifier in self.classifiers]
        classifier_probs = [max(classifier.predict_proba([domain_feature])[0]) for classifier in self.classifiers]
        
        if(max(classifier_preds, key=classifier_preds.count) == 0):
            tableViewPart['row_color'] = QColor(238, 75, 43)
            tableViewPart['category'] = "Malicious"
        else:
            tableViewPart['row_color'] = QColor(94, 247, 155)
            tableViewPart['category'] = "Benign"
            
        clusterer_preds = [clusterer.predict([domain_feature])[0] for clusterer in self.clusterers]
        clusterer_probs = [clusterer.predict_proba([domain_feature])[0] for clusterer in self.clusterers]
        #print(repr(packet[DNS]), '\n\n')
        
        QApplication.processEvents()   
        self.packetData.emit((tableViewPart, domain_feature, classifier_preds, classifier_probs, clusterer_preds))
        
    def startSniff(self):
        while(self.end == False):
            QApplication.processEvents()
            self.pkts = sniff(
                count=0,
                prn=self.handlePacket,
                timeout=1,
                filter='udp and port 53',
                stop_filter=lambda x: self.sniffStatus()
            )
            QApplication.processEvents()