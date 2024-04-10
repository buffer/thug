#!/usr/bin/env python

# This code is derived from the awesome VBE Decoder authored by Didier Stevens
# and available at https://github.com/DidierStevens/DidierStevensSuite

import re


DDECODE = {}
DDECODE[9] = "\x57\x6e\x7b"
DDECODE[10] = "\x4a\x4c\x41"
DDECODE[11] = "\x0b\x0b\x0b"
DDECODE[12] = "\x0c\x0c\x0c"
DDECODE[13] = "\x4a\x4c\x41"
DDECODE[14] = "\x0e\x0e\x0e"
DDECODE[15] = "\x0f\x0f\x0f"
DDECODE[16] = "\x10\x10\x10"
DDECODE[17] = "\x11\x11\x11"
DDECODE[18] = "\x12\x12\x12"
DDECODE[19] = "\x13\x13\x13"
DDECODE[20] = "\x14\x14\x14"
DDECODE[21] = "\x15\x15\x15"
DDECODE[22] = "\x16\x16\x16"
DDECODE[23] = "\x17\x17\x17"
DDECODE[24] = "\x18\x18\x18"
DDECODE[25] = "\x19\x19\x19"
DDECODE[26] = "\x1a\x1a\x1a"
DDECODE[27] = "\x1b\x1b\x1b"
DDECODE[28] = "\x1c\x1c\x1c"
DDECODE[29] = "\x1d\x1d\x1d"
DDECODE[30] = "\x1e\x1e\x1e"
DDECODE[31] = "\x1f\x1f\x1f"
DDECODE[32] = "\x2e\x2d\x32"
DDECODE[33] = "\x47\x75\x30"
DDECODE[34] = "\x7a\x52\x21"
DDECODE[35] = "\x56\x60\x29"
DDECODE[36] = "\x42\x71\x5b"
DDECODE[37] = "\x6a\x5e\x38"
DDECODE[38] = "\x2f\x49\x33"
DDECODE[39] = "\x26\x5c\x3d"
DDECODE[40] = "\x49\x62\x58"
DDECODE[41] = "\x41\x7d\x3a"
DDECODE[42] = "\x34\x29\x35"
DDECODE[43] = "\x32\x36\x65"
DDECODE[44] = "\x5b\x20\x39"
DDECODE[45] = "\x76\x7c\x5c"
DDECODE[46] = "\x72\x7a\x56"
DDECODE[47] = "\x43\x7f\x73"
DDECODE[48] = "\x38\x6b\x66"
DDECODE[49] = "\x39\x63\x4e"
DDECODE[50] = "\x70\x33\x45"
DDECODE[51] = "\x45\x2b\x6b"
DDECODE[52] = "\x68\x68\x62"
DDECODE[53] = "\x71\x51\x59"
DDECODE[54] = "\x4f\x66\x78"
DDECODE[55] = "\x09\x76\x5e"
DDECODE[56] = "\x62\x31\x7d"
DDECODE[57] = "\x44\x64\x4a"
DDECODE[58] = "\x23\x54\x6d"
DDECODE[59] = "\x75\x43\x71"
DDECODE[60] = "\x4a\x4c\x41"
DDECODE[61] = "\x7e\x3a\x60"
DDECODE[62] = "\x4a\x4c\x41"
DDECODE[63] = "\x5e\x7e\x53"
DDECODE[64] = "\x40\x4c\x40"
DDECODE[65] = "\x77\x45\x42"
DDECODE[66] = "\x4a\x2c\x27"
DDECODE[67] = "\x61\x2a\x48"
DDECODE[68] = "\x5d\x74\x72"
DDECODE[69] = "\x22\x27\x75"
DDECODE[70] = "\x4b\x37\x31"
DDECODE[71] = "\x6f\x44\x37"
DDECODE[72] = "\x4e\x79\x4d"
DDECODE[73] = "\x3b\x59\x52"
DDECODE[74] = "\x4c\x2f\x22"
DDECODE[75] = "\x50\x6f\x54"
DDECODE[76] = "\x67\x26\x6a"
DDECODE[77] = "\x2a\x72\x47"
DDECODE[78] = "\x7d\x6a\x64"
DDECODE[79] = "\x74\x39\x2d"
DDECODE[80] = "\x54\x7b\x20"
DDECODE[81] = "\x2b\x3f\x7f"
DDECODE[82] = "\x2d\x38\x2e"
DDECODE[83] = "\x2c\x77\x4c"
DDECODE[84] = "\x30\x67\x5d"
DDECODE[85] = "\x6e\x53\x7e"
DDECODE[86] = "\x6b\x47\x6c"
DDECODE[87] = "\x66\x34\x6f"
DDECODE[88] = "\x35\x78\x79"
DDECODE[89] = "\x25\x5d\x74"
DDECODE[90] = "\x21\x30\x43"
DDECODE[91] = "\x64\x23\x26"
DDECODE[92] = "\x4d\x5a\x76"
DDECODE[93] = "\x52\x5b\x25"
DDECODE[94] = "\x63\x6c\x24"
DDECODE[95] = "\x3f\x48\x2b"
DDECODE[96] = "\x7b\x55\x28"
DDECODE[97] = "\x78\x70\x23"
DDECODE[98] = "\x29\x69\x41"
DDECODE[99] = "\x28\x2e\x34"
DDECODE[100] = "\x73\x4c\x09"
DDECODE[101] = "\x59\x21\x2a"
DDECODE[102] = "\x33\x24\x44"
DDECODE[103] = "\x7f\x4e\x3f"
DDECODE[104] = "\x6d\x50\x77"
DDECODE[105] = "\x55\x09\x3b"
DDECODE[106] = "\x53\x56\x55"
DDECODE[107] = "\x7c\x73\x69"
DDECODE[108] = "\x3a\x35\x61"
DDECODE[109] = "\x5f\x61\x63"
DDECODE[110] = "\x65\x4b\x50"
DDECODE[111] = "\x46\x58\x67"
DDECODE[112] = "\x58\x3b\x51"
DDECODE[113] = "\x31\x57\x49"
DDECODE[114] = "\x69\x22\x4f"
DDECODE[115] = "\x6c\x6d\x46"
DDECODE[116] = "\x5a\x4d\x68"
DDECODE[117] = "\x48\x25\x7c"
DDECODE[118] = "\x27\x28\x36"
DDECODE[119] = "\x5c\x46\x70"
DDECODE[120] = "\x3d\x4a\x6e"
DDECODE[121] = "\x24\x32\x7a"
DDECODE[122] = "\x79\x41\x2f"
DDECODE[123] = "\x37\x3d\x5f"
DDECODE[124] = "\x60\x5f\x4b"
DDECODE[125] = "\x51\x4f\x5a"
DDECODE[126] = "\x20\x42\x2c"
DDECODE[127] = "\x36\x65\x57"

DCOMBINATION = {}
DCOMBINATION[0] = 0
DCOMBINATION[1] = 1
DCOMBINATION[2] = 2
DCOMBINATION[3] = 0
DCOMBINATION[4] = 1
DCOMBINATION[5] = 2
DCOMBINATION[6] = 1
DCOMBINATION[7] = 2
DCOMBINATION[8] = 2
DCOMBINATION[9] = 1
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
    subs = (("@&", chr(10)), ("@#", chr(13)), ("@*", ">"), ("@!", "<"), ("@$", "@"))

    def decode(self, data):
        result = ""
        index = -1

        match = re.search(r"#@~\^......==(.+)......==\^#~@", data)
        if not match:
            return result

        script = match.groups()[0]

        for p, v in self.subs:
            script = script.replace(p, v)

        for char in script:
            byte = ord(char)

            if byte < 128:
                index = index + 1

            if (
                (byte == 9 or byte > 31 and byte < 128)
                and byte != 60
                and byte != 62
                and byte != 64
            ):  # pylint:disable=too-many-boolean-expressions,chained-comparison
                char = [c for c in DDECODE[byte]][DCOMBINATION[index % 64]]  # pylint:disable=unnecessary-comprehension

            result += char

        return result
