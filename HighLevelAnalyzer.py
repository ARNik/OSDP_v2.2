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

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'mytype': {
            'format': '{{data.string}}'
        }
    }

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''
        t = int("0x53", 0)
        print('t: ', t)

        print("OSDP settings:", self.my_string_setting,
              self.my_number_setting, self.my_choices_setting)

    def decode(self, frame: AnalyzerFrame):
        try:
            ch = frame.data['data']
        except:
            # Not an ASCII character
            return

        print('ch: ', ch)
        if self.byte_cnt == 0:
            print('SOM search...')
            if ch == b'\x53':
                self.byte_cnt = 1
                print(self.byte_cnt)
                return AnalyzerFrame('mytype', frame.start_time, frame.end_time, {
                    'string': 'SOM'
                })
            else:
                return
        elif self.byte_cnt == 1:
            self.byte_cnt += 1
            return AnalyzerFrame('mytype', frame.start_time, frame.end_time, {
                'string': 'ADDR'
            })
        else:
            self.byte_cnt += 1
            print(self.byte_cnt)
            return AnalyzerFrame('mytype', frame.start_time, frame.end_time, {
                'string': str(self.byte_cnt)
            })



