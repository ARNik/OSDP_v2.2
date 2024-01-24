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
    len_lsb = 0
    len_start_time = 0
    len_all = 0

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
            self.len_lsb = ch[0]
            self.len_start_time = frame.start_time
            self.byte_cnt += 1
            return
            # msg = AnalyzerFrame('mytype', frame.start_time, frame.end_time, {'string': 'LEN_LSB'})
        elif self.byte_cnt == 3:
            self.len_all = self.len_lsb + ch[0]
            len = 'LEN: ' + str(self.len_all)
            print(len)
            msg = AnalyzerFrame('mytype', self.len_start_time, frame.end_time, {'string': len})
        elif self.byte_cnt == 4:
            msg = AnalyzerFrame('mytype', frame.start_time, frame.end_time, {'string': 'CTRL'})
        else:
            msg = AnalyzerFrame('mytype', frame.start_time, frame.end_time, {'string': str(self.byte_cnt + 1)})

        self.byte_cnt += 1

        if self.len_all > 0:
            if self.len_all == self.byte_cnt:
                self.len_all = 0
                self.byte_cnt = 0

        return msg



