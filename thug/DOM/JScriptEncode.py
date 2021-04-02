#!/usr/bin/env python

# This code is derived from the awesome VBE Decoder authored by Didier Stevens
# and available at https://github.com/DidierStevens/DidierStevensSuite

import re


DDECODE     = dict()
DDECODE[9]  = '\x57\x6E\x7B'
DDECODE[10] = '\x4A\x4C\x41'
DDECODE[11] = '\x0B\x0B\x0B'
DDECODE[12] = '\x0C\x0C\x0C'
DDECODE[13] = '\x4A\x4C\x41'
DDECODE[14] = '\x0E\x0E\x0E'
DDECODE[15] = '\x0F\x0F\x0F'
DDECODE[16] = '\x10\x10\x10'
DDECODE[17] = '\x11\x11\x11'
DDECODE[18] = '\x12\x12\x12'
DDECODE[19] = '\x13\x13\x13'
DDECODE[20] = '\x14\x14\x14'
DDECODE[21] = '\x15\x15\x15'
DDECODE[22] = '\x16\x16\x16'
DDECODE[23] = '\x17\x17\x17'
DDECODE[24] = '\x18\x18\x18'
DDECODE[25] = '\x19\x19\x19'
DDECODE[26] = '\x1A\x1A\x1A'
DDECODE[27] = '\x1B\x1B\x1B'
DDECODE[28] = '\x1C\x1C\x1C'
DDECODE[29] = '\x1D\x1D\x1D'
DDECODE[30] = '\x1E\x1E\x1E'
DDECODE[31] = '\x1F\x1F\x1F'
DDECODE[32] = '\x2E\x2D\x32'
DDECODE[33] = '\x47\x75\x30'
DDECODE[34] = '\x7A\x52\x21'
DDECODE[35] = '\x56\x60\x29'
DDECODE[36] = '\x42\x71\x5B'
DDECODE[37] = '\x6A\x5E\x38'
DDECODE[38] = '\x2F\x49\x33'
DDECODE[39] = '\x26\x5C\x3D'
DDECODE[40] = '\x49\x62\x58'
DDECODE[41] = '\x41\x7D\x3A'
DDECODE[42] = '\x34\x29\x35'
DDECODE[43] = '\x32\x36\x65'
DDECODE[44] = '\x5B\x20\x39'
DDECODE[45] = '\x76\x7C\x5C'
DDECODE[46] = '\x72\x7A\x56'
DDECODE[47] = '\x43\x7F\x73'
DDECODE[48] = '\x38\x6B\x66'
DDECODE[49] = '\x39\x63\x4E'
DDECODE[50] = '\x70\x33\x45'
DDECODE[51] = '\x45\x2B\x6B'
DDECODE[52] = '\x68\x68\x62'
DDECODE[53] = '\x71\x51\x59'
DDECODE[54] = '\x4F\x66\x78'
DDECODE[55] = '\x09\x76\x5E'
DDECODE[56] = '\x62\x31\x7D'
DDECODE[57] = '\x44\x64\x4A'
DDECODE[58] = '\x23\x54\x6D'
DDECODE[59] = '\x75\x43\x71'
DDECODE[60] = '\x4A\x4C\x41'
DDECODE[61] = '\x7E\x3A\x60'
DDECODE[62] = '\x4A\x4C\x41'
DDECODE[63] = '\x5E\x7E\x53'
DDECODE[64] = '\x40\x4C\x40'
DDECODE[65] = '\x77\x45\x42'
DDECODE[66] = '\x4A\x2C\x27'
DDECODE[67] = '\x61\x2A\x48'
DDECODE[68] = '\x5D\x74\x72'
DDECODE[69] = '\x22\x27\x75'
DDECODE[70] = '\x4B\x37\x31'
DDECODE[71] = '\x6F\x44\x37'
DDECODE[72] = '\x4E\x79\x4D'
DDECODE[73] = '\x3B\x59\x52'
DDECODE[74] = '\x4C\x2F\x22'
DDECODE[75] = '\x50\x6F\x54'
DDECODE[76] = '\x67\x26\x6A'
DDECODE[77] = '\x2A\x72\x47'
DDECODE[78] = '\x7D\x6A\x64'
DDECODE[79] = '\x74\x39\x2D'
DDECODE[80] = '\x54\x7B\x20'
DDECODE[81] = '\x2B\x3F\x7F'
DDECODE[82] = '\x2D\x38\x2E'
DDECODE[83] = '\x2C\x77\x4C'
DDECODE[84] = '\x30\x67\x5D'
DDECODE[85] = '\x6E\x53\x7E'
DDECODE[86] = '\x6B\x47\x6C'
DDECODE[87] = '\x66\x34\x6F'
DDECODE[88] = '\x35\x78\x79'
DDECODE[89] = '\x25\x5D\x74'
DDECODE[90] = '\x21\x30\x43'
DDECODE[91] = '\x64\x23\x26'
DDECODE[92] = '\x4D\x5A\x76'
DDECODE[93] = '\x52\x5B\x25'
DDECODE[94] = '\x63\x6C\x24'
DDECODE[95] = '\x3F\x48\x2B'
DDECODE[96] = '\x7B\x55\x28'
DDECODE[97] = '\x78\x70\x23'
DDECODE[98] = '\x29\x69\x41'
DDECODE[99] = '\x28\x2E\x34'
DDECODE[100] = '\x73\x4C\x09'
DDECODE[101] = '\x59\x21\x2A'
DDECODE[102] = '\x33\x24\x44'
DDECODE[103] = '\x7F\x4E\x3F'
DDECODE[104] = '\x6D\x50\x77'
DDECODE[105] = '\x55\x09\x3B'
DDECODE[106] = '\x53\x56\x55'
DDECODE[107] = '\x7C\x73\x69'
DDECODE[108] = '\x3A\x35\x61'
DDECODE[109] = '\x5F\x61\x63'
DDECODE[110] = '\x65\x4B\x50'
DDECODE[111] = '\x46\x58\x67'
DDECODE[112] = '\x58\x3B\x51'
DDECODE[113] = '\x31\x57\x49'
DDECODE[114] = '\x69\x22\x4F'
DDECODE[115] = '\x6C\x6D\x46'
DDECODE[116] = '\x5A\x4D\x68'
DDECODE[117] = '\x48\x25\x7C'
DDECODE[118] = '\x27\x28\x36'
DDECODE[119] = '\x5C\x46\x70'
DDECODE[120] = '\x3D\x4A\x6E'
DDECODE[121] = '\x24\x32\x7A'
DDECODE[122] = '\x79\x41\x2F'
DDECODE[123] = '\x37\x3D\x5F'
DDECODE[124] = '\x60\x5F\x4B'
DDECODE[125] = '\x51\x4F\x5A'
DDECODE[126] = '\x20\x42\x2C'
DDECODE[127] = '\x36\x65\x57'

DCOMBINATION    = dict()
DCOMBINATION[0]  = 0
DCOMBINATION[1]  = 1
DCOMBINATION[2]  = 2
DCOMBINATION[3]  = 0
DCOMBINATION[4]  = 1
DCOMBINATION[5]  = 2
DCOMBINATION[6]  = 1
DCOMBINATION[7]  = 2
DCOMBINATION[8]  = 2
DCOMBINATION[9]  = 1
DCOMBINATION[10] = 2
DCOMBINATION[11] = 1
DCOMBINATION[12] = 0
DCOMBINATION[13] = 2
DCOMBINATION[14] = 1
DCOMBINATION[15] = 2
DCOMBINATION[16] = 0
DCOMBINATION[17] = 2
DCOMBINATION[18] = 1
DCOMBINATION[19] = 2
DCOMBINATION[20] = 0
DCOMBINATION[21] = 0
DCOMBINATION[22] = 1
DCOMBINATION[23] = 2
DCOMBINATION[24] = 2
DCOMBINATION[25] = 1
DCOMBINATION[26] = 0
DCOMBINATION[27] = 2
DCOMBINATION[28] = 1
DCOMBINATION[29] = 2
DCOMBINATION[30] = 2
DCOMBINATION[31] = 1
DCOMBINATION[32] = 0
DCOMBINATION[33] = 0
DCOMBINATION[34] = 2
DCOMBINATION[35] = 1
DCOMBINATION[36] = 2
DCOMBINATION[37] = 1
DCOMBINATION[38] = 2
DCOMBINATION[39] = 0
DCOMBINATION[40] = 2
DCOMBINATION[41] = 0
DCOMBINATION[42] = 0
DCOMBINATION[43] = 1
DCOMBINATION[44] = 2
DCOMBINATION[45] = 0
DCOMBINATION[46] = 2
DCOMBINATION[47] = 1
DCOMBINATION[48] = 0
DCOMBINATION[49] = 2
DCOMBINATION[50] = 1
DCOMBINATION[51] = 2
DCOMBINATION[52] = 0
DCOMBINATION[53] = 0
DCOMBINATION[54] = 1
DCOMBINATION[55] = 2
DCOMBINATION[56] = 2
DCOMBINATION[57] = 0
DCOMBINATION[58] = 0
DCOMBINATION[59] = 1
DCOMBINATION[60] = 2
DCOMBINATION[61] = 0
DCOMBINATION[62] = 2
DCOMBINATION[63] = 1


class JScriptEncode:
    subs = (('@&', chr(10)),
            ('@#', chr(13)),
            ('@*', '>'),
            ('@!', '<'),
            ('@$', '@'))

    def decode(self, data):
        result = ""
        index  = -1

        match = re.search(r'#@~\^......==(.+)......==\^#~@', data)
        if not match:
            return result

        script = match.groups()[0]

        for (p, v) in self.subs:
            script = script.replace(p, v)

        for char in script:
            byte = ord(char)

            if byte < 128:
                index = index + 1

            if (byte == 9 or byte > 31 and byte < 128) and byte != 60 and byte != 62 and byte != 64:
                char = [c for c in DDECODE[byte]][DCOMBINATION[index % 64]]

            result += char

        return result
