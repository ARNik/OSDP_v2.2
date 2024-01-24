# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    my_string_setting = StringSetting()
    my_number_setting = NumberSetting(min_value=0, max_value=100)
    my_choices_setting = ChoicesSetting(choices=('A', 'B'))

    byte_cnt = 0
    pkt_len_lsb = 0
    pkt_len_start_time = 0
    pkt_len = 0
    pkt_sum = ''
    pkt_scb = ''

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'mytype': {
            'format': '{{data.string}}'
        }
    }

    def __init__(self):
        print("OSDP settings:", self.my_string_setting,
              self.my_number_setting, self.my_choices_setting)

    def decode(self, frame: AnalyzerFrame):
        try:
            ch = frame.data['data']
        except:
            # Not an ASCII character
            return

        msg = AnalyzerFrame('mytype', frame.start_time, frame.end_time, {})

        if self.byte_cnt == 0:
            print('SOM search...')
            if ch == b'\x53':
                msg = AnalyzerFrame('mytype', frame.start_time, frame.end_time, {'string': 'SOM'})
            else:
                return
        elif self.byte_cnt == 1:
            addr = 'ADDR: ' + str(ch[0])
            print(addr)
            msg = AnalyzerFrame('mytype', frame.start_time, frame.end_time, {'string': addr})
        elif self.byte_cnt == 2:
            self.pkt_len_lsb = ch[0]
            self.pkt_len_start_time = frame.start_time
            self.byte_cnt += 1
            return
        elif self.byte_cnt == 3:
            self.pkt_len = self.pkt_len_lsb + ch[0]
            len = 'LEN: ' + str(self.pkt_len)
            print(len)
            msg = AnalyzerFrame('mytype', self.pkt_len_start_time, frame.end_time, {'string': len})
        elif self.byte_cnt == 4:
            sqn = ch[0] & 3
            self.pkt_sum = ch[0] & 4
            if self.pkt_sum:
                sum = 'CRC'
            else:
                sum = 'CHECKSUM'
            self.pkt_scb = ch[0] & 8
            if self.pkt_scb:
                scb = 'SCB'
            else:
                scb = 'noSCB'
            ctrl = 'CTRL (' + 'SQN: ' + str(sqn) + ', ' + sum + ', ' + scb + ')'
            msg = AnalyzerFrame('mytype', frame.start_time, frame.end_time, {'string': ctrl})
        else:
            msg = AnalyzerFrame('mytype', frame.start_time, frame.end_time, {'string': str(self.byte_cnt + 1)})

        self.byte_cnt += 1

        if self.pkt_len > 0:
            if self.pkt_len == self.byte_cnt:
                self.pkt_len = 0
                self.byte_cnt = 0

        return msg



