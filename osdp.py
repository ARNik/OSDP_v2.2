# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting


# High level analyzers must subclass the HighLevelAnalyzer class.
class OSDP_Analyzer(HighLevelAnalyzer):

    byte_cnt = 0            # byte counter for the current packet
    pkt_start_time = 0      # for storing packet start times for multibyte messages
    pkt_len = 0             # current packet length
    pkt_crc = False         # if current packet has crc (or checksum)
    pkt_scb = False         # if current packet has Security Control Block
    pkt_cmd = ''            # current command
    pd_sn = 0               # pd serial number
    pd_fw_version = ''      # pd firmware version
    pd_cap_msg = ''         # pd capability for PDCAP parsing

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'mytype': {
            'format': '{{data.string}}'
        }
    }

    def __init__(self):
        print('Init')

    def decode(self, frame: AnalyzerFrame):
        try:
            ch = frame.data['data'][0]
        except:
            # Not an ASCII character
            return

        msg = AnalyzerFrame('mytype', frame.start_time, frame.end_time, {})

        if self.byte_cnt == 0:
            if ch == 0x53:
                print('SOM')
                msg = AnalyzerFrame('mytype', frame.start_time, frame.end_time, {'string': 'SOM'})
            else:
                return
        elif self.byte_cnt == 1:
            addr = 'ADDR: '
            if (ch & 0x7F) == 0x7F:
                addr += 'BROADCAST'
            else:
                addr += str(ch & 0x7F)
            if (ch & 0x80):
                addr += ' REPLY'
            print(addr)
            msg = AnalyzerFrame('mytype', frame.start_time, frame.end_time, {'string': addr})
        elif self.byte_cnt == 2:
            self.pkt_len = ch
            self.pkt_start_time = frame.start_time
            self.byte_cnt += 1
            return
        elif self.byte_cnt == 3:
            self.pkt_len = self.pkt_len + (ch << 8)
            if self.pkt_len > 1440:
                self.byte_cnt = 0
                return
            len = 'LEN: ' + str(self.pkt_len)
            print(len)
            msg = AnalyzerFrame('mytype', self.pkt_start_time, frame.end_time, {'string': len})
        elif self.byte_cnt == 4:
            sqn = ch & 3
            self.pkt_crc = bool(ch & 4)
            if self.pkt_crc:
                sum = 'CRC'
            else:
                sum = 'CHECKSUM'
            self.pkt_scb = bool(ch & 8)
            if self.pkt_scb:
                scb = 'SCB'
            else:
                scb = 'noSCB'
            ctrl = 'CTRL (' + 'SQN: ' + str(sqn) + ', ' + sum + ', ' + scb + ')'
            msg = AnalyzerFrame('mytype', frame.start_time, frame.end_time, {'string': ctrl})
        else:
            # Header parsed
            if self.pkt_scb:
                msg = AnalyzerFrame('mytype', frame.start_time, frame.end_time, {'string': str(self.byte_cnt + 1)})
            else:
                if self.byte_cnt == 5:  # if cmd/reply byte
                    self.pkt_cmd = self.GetCmdReplyCode(ch)
                    print(self.pkt_cmd)
                    msg = AnalyzerFrame('mytype', frame.start_time, frame.end_time, {'string': self.pkt_cmd})
                else:
                    # print('sum: ', str(self.pkt_crc), ' cnt: ', self.byte_cnt, ' len: ', self.pkt_len)
                    if self.pkt_crc and self.byte_cnt == (self.pkt_len - 2):
                        self.pkt_start_time = frame.start_time
                        self.byte_cnt += 1
                        return
                    elif self.pkt_crc and self.byte_cnt == (self.pkt_len - 1):
                        msg = AnalyzerFrame('mytype', self.pkt_start_time, frame.end_time, {'string': 'CRC'})
                    elif not self.pkt_crc and self.byte_cnt == (self.pkt_len - 1):
                        msg = AnalyzerFrame('mytype', frame.start_time, frame.end_time, {'string': 'CHECKSUM'})
                    else:
                        # Command/Reply parsing
                        if self.pkt_cmd == 'ID':
                            if ch == 0x00:
                                msg = AnalyzerFrame('mytype', frame.start_time, frame.end_time, {'string': 'Standard'})
                            else:
                                msg = AnalyzerFrame('mytype', frame.start_time, frame.end_time, {'string': 'Unknown'})
                        elif self.pkt_cmd == 'CAP':
                            if ch == 0x00:
                                msg = AnalyzerFrame('mytype', frame.start_time, frame.end_time, {'string': 'Standard'})
                            else:
                                msg = AnalyzerFrame('mytype', frame.start_time, frame.end_time, {'string': 'Unknown'})
                        elif self.pkt_cmd == 'PDID':
                            if self.byte_cnt == 6:
                                self.pkt_start_time = frame.start_time
                                self.byte_cnt += 1
                                return
                            elif self.byte_cnt == 7:
                                self.byte_cnt += 1
                                return
                            elif self.byte_cnt == 8:
                                msg = AnalyzerFrame('mytype', self.pkt_start_time, frame.end_time, {'string': 'Vendor Code'})
                            elif self.byte_cnt == 9:
                                msg = AnalyzerFrame('mytype', frame.start_time, frame.end_time, {'string': 'Model'})
                            elif self.byte_cnt == 10:
                                msg = AnalyzerFrame('mytype', frame.start_time, frame.end_time, {'string': 'Version'})
                            elif self.byte_cnt == 11:
                                self.pd_sn = ch
                                self.pkt_start_time = frame.start_time
                                self.byte_cnt += 1
                                return
                            elif self.byte_cnt == 12:
                                self.pd_sn += (ch << 8)
                                self.byte_cnt += 1
                                return
                            elif self.byte_cnt == 13:
                                self.pd_sn += (ch << 16)
                                self.byte_cnt += 1
                                return
                            elif self.byte_cnt == 14:
                                self.pd_sn += (ch << 24)
                                sn = 'SN: ' + str(self.pd_sn)
                                msg = AnalyzerFrame('mytype', self.pkt_start_time, frame.end_time, {'string': sn})
                            elif self.byte_cnt == 15:
                                self.pd_fw_version = 'FW: v' + str(ch)
                                self.pkt_start_time = frame.start_time
                                self.byte_cnt += 1
                                return
                            elif self.byte_cnt == 16:
                                self.pd_fw_version += '.' + str(ch)
                                self.byte_cnt += 1
                                return
                            elif self.byte_cnt == 17:
                                self.pd_fw_version += '.' + str(ch)
                                msg = AnalyzerFrame('mytype', self.pkt_start_time, frame.end_time, {'string': self.pd_fw_version})
                        elif self.pkt_cmd == 'PDCAP':
                            if (self.byte_cnt % 3) == 0:
                                self.pd_cap_msg = self.PDCAPparse(ch)
                                self.pkt_start_time = frame.start_time
                                self.byte_cnt += 1
                                return
                            elif (self.byte_cnt % 3) == 1:
                                self.byte_cnt += 1
                                return
                            elif (self.byte_cnt % 3) == 2:
                                msg = AnalyzerFrame('mytype', self.pkt_start_time, frame.end_time, {'string': self.pd_cap_msg})
                            else:
                                msg = AnalyzerFrame('mytype', frame.start_time, frame.end_time, {'string': 'PDCAP parsing error'})
                        elif self.pkt_cmd == 'LSTATR':
                            if ch == 0x00:
                                msg = AnalyzerFrame('mytype', frame.start_time, frame.end_time, {'string': 'Normal'})
                            elif ch == 0x01 and self.byte_cnt == 6:
                                msg = AnalyzerFrame('mytype', frame.start_time, frame.end_time, {'string': 'tamper'})
                            elif ch == 0x01 and self.byte_cnt == 7:
                                msg = AnalyzerFrame('mytype', frame.start_time, frame.end_time, {'string': 'power'})
                            else:
                                msg = AnalyzerFrame('mytype', frame.start_time, frame.end_time, {'string': 'Unknown'})

        self.byte_cnt += 1

        if self.pkt_len > 0:
            if self.pkt_len == self.byte_cnt:
                self.pkt_len = 0
                self.byte_cnt = 0

        return msg


    def GetCmdReplyCode(self, cmd):
        # Commands                              # Meaning (Data)
        if cmd == 0x60:  return 'POLL'          # Poll (None)
        if cmd == 0x61:  return 'ID'            # ID Report Request (id type)
        if cmd == 0x62:  return 'CAP'           # PD Capabilities Request (Reply type)
        if cmd == 0x64:  return 'LSTAT'         # Local Status Report Request (None)
        if cmd == 0x65:  return 'ISTAT'         # Input Status Report Request (None)
        if cmd == 0x66:  return 'OSTAT'         # Output Status Report Request (None)
        if cmd == 0x67:  return 'RSTAT'         # Reader Status Report Request (None)
        if cmd == 0x68:  return 'OUT'           # Output Control Command (Output settings)
        if cmd == 0x69:  return 'LED'           # Reader Led Control Command (LED settings)
        if cmd == 0x6A:  return 'BUZ'           # Reader Buzzer Control Command (Buzzer settings)
        if cmd == 0x6B:  return 'TEXT'          # Text Output Command (Text settings)
        if cmd == 0x6E:  return 'COMSET'        # PD Communication Configuration Command (Com settings)
        if cmd == 0x73:  return 'BIOREAD'       # Scan and Send Biometric Data (Requested Return Format)
        if cmd == 0x74:  return 'BIOMATCH'      # Scan and Match Biometric Template (Biometric Template)
        if cmd == 0x75:  return 'KEYSET'        # Encryption Key Set Command (Encryption Key)
        if cmd == 0x76:  return 'CHLNG'         # Challenge and Secure Session Initialization Rq. (Challenge Data)
        if cmd == 0x77:  return 'SCRYPT'        # Server Cryptogram (Encryption Data)
        if cmd == 0x7B:  return 'ACURXSIZE'     # Max ACU receive size (Buffer size)
        if cmd == 0x7C:  return 'FILETRANSFER'  # Send data file to PD (File contents)
        if cmd == 0x80:  return 'MFG'           # Manufacturer Specific Command (Any)
        if cmd == 0xA1:  return 'XWR'           # Extended write data (APDU and details)
        if cmd == 0xA2:  return 'ABORT'         # Abort PD operation (None)
        if cmd == 0xA3:  return 'PIVDATA'       # Get PIV Data (Object details)
        if cmd == 0xA4:  return 'GENAUTH'       # Request Authenticate (Request details)
        if cmd == 0xA5:  return 'CRAUTH'        # Request Crypto Response (Challenge details)
        if cmd == 0xA7:  return 'KEEPACTIVE'    # PD read activation (Time duration)

        # Replies                               # Meaning (Data)
        if cmd == 0x40:  return 'ACK'           # Command accepted, nothing else to report (None)
        if cmd == 0x41:  return 'NAK'           # Command not processed (Reason for rejecting command)
        if cmd == 0x45:  return 'PDID'          # PD ID Report (Report data)
        if cmd == 0x46:  return 'PDCAP'         # PD Capabilities Report (Report data)
        if cmd == 0x48:  return 'LSTATR'        # Local Status Report (Report data)
        if cmd == 0x49:  return 'ISTATR'        # Input Status Report (Report data)
        if cmd == 0x4A:  return 'OSTATR'        # Output Status Report (Report data)
        if cmd == 0x4B:  return 'RSTATR'        # Reader Status Report (Report data)
        if cmd == 0x50:  return 'RAW'           # Reader Data – Raw bit image of card data (Card data)
        if cmd == 0x51:  return 'FMT'           # Reader Data – Formatted character stream (Card data)
        if cmd == 0x53:  return 'KEYPAD'        # Keypad Data (Keypad data)
        if cmd == 0x54:  return 'COM'           # PD Communications Configuration Report (Comm data)
        if cmd == 0x57:  return 'BIOREADR'      # Biometric Data (Biometric data)
        if cmd == 0x58:  return 'BIOMATCHR'     # Biometric Match Result (Result)
        if cmd == 0x76:  return 'CCRYPT'        # Client's ID, Random Number, and Cryptogram (Encryption Data)
        if cmd == 0x79:  return 'BUSY'          # PD is Busy reply
        if cmd == 0x78:  return 'RMAC_I'        # Initial R-MAC (Encryption Data)
        if cmd == 0x7A:  return 'FTSTAT'        # File transfer status (Status details)
        if cmd == 0x80:  return 'PIVDATAR'      # PIV Data Reply (credential data)
        if cmd == 0x81:  return 'GENAUTHR'      # Authentication response (response details)
        if cmd == 0x82:  return 'CRAUTHR'       # Response to challenge (response details)
        if cmd == 0x83:  return 'MFGSTATR'      # MFG specific status (status details)
        if cmd == 0x84:  return 'MFGERRR'       # MFG specific error (error details)
        if cmd == 0x90:  return 'MFGREP'        # Manufacturer Specific Reply (Any)
        if cmd == 0xB1:  return 'XRD'           # Extended Read Response (APDU and details)
        return 'Unknown'
    

    def PDCAPparse(self, fn_code):
        res = ''
        if fn_code == 1:
            res += 'Contact Status Monitoring'
        elif fn_code == 2:
            res += 'Output Control'
        elif fn_code == 3:
            res += 'Card Data Format'
        elif fn_code == 4:
            res += 'Reader LED Control'
        elif fn_code == 5:
            res += 'Reader Audible Output'
        elif fn_code == 6:
            res += 'Reader Text Output'
        elif fn_code == 7:
            res += 'Time Keeping'
        elif fn_code == 8:
            res += 'Check Character Support'
        elif fn_code == 9:
            res += 'Communication Security'
        elif fn_code == 10:
            res += 'Receive BufferSize'
        elif fn_code == 11:
            res += 'Largest Combined Message Size'
        elif fn_code == 12:
            res += 'Smart Card Support'
        elif fn_code == 13:
            res += 'Readers'
        elif fn_code == 14:
            res += 'Biometrics'
        elif fn_code == 15:
            res += 'Secure PIN Entry support'
        elif fn_code == 16:
            res += 'OSDP Version'
        else:
            res += 'Unkonwn'
        return res

