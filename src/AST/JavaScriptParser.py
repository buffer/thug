# $ANTLR 3.1.3 October 14, 2010 12:41:46 /home/buffer/antlr/JavaScript.g 2010-10-14 12:43:20

import sys
from antlr3 import *
from antlr3.compat import set, frozenset

from antlr3.tree import *



# for convenience in actions
HIDDEN = BaseRecognizer.HIDDEN

# token types
LT=4
DecimalDigit=17
EOF=-1
Identifier=5
SingleStringCharacter=9
T__93=93
T__94=94
T__91=91
T__92=92
T__90=90
Comment=28
SingleEscapeCharacter=14
UnicodeLetter=24
ExponentPart=21
WhiteSpace=30
T__99=99
T__98=98
T__97=97
T__96=96
UnicodeCombiningMark=27
T__95=95
UnicodeDigit=25
T__80=80
T__81=81
NumericLiteral=7
T__82=82
T__83=83
IdentifierStart=22
DoubleStringCharacter=8
T__85=85
T__84=84
T__87=87
T__86=86
T__89=89
T__88=88
T__71=71
T__72=72
T__70=70
CharacterEscapeSequence=11
T__76=76
T__75=75
T__74=74
T__73=73
EscapeSequence=10
T__79=79
UnicodeConnectorPunctuation=26
T__78=78
T__77=77
T__68=68
T__69=69
T__66=66
T__67=67
T__64=64
T__65=65
T__62=62
T__63=63
HexEscapeSequence=12
LineComment=29
T__61=61
T__60=60
HexDigit=18
T__55=55
T__56=56
T__57=57
T__58=58
T__51=51
T__52=52
T__53=53
T__54=54
T__59=59
T__103=103
T__104=104
T__105=105
T__106=106
EscapeCharacter=16
T__50=50
IdentifierPart=23
T__42=42
T__43=43
T__40=40
T__41=41
T__46=46
T__47=47
T__44=44
T__45=45
T__48=48
T__49=49
UnicodeEscapeSequence=13
T__102=102
T__101=101
T__100=100
DecimalLiteral=19
StringLiteral=6
T__31=31
T__32=32
T__33=33
T__34=34
T__35=35
T__36=36
T__37=37
T__38=38
T__39=39
HexIntegerLiteral=20
NonEscapeCharacter=15

# token names
tokenNames = [
    "<invalid>", "<EOR>", "<DOWN>", "<UP>", 
    "LT", "Identifier", "StringLiteral", "NumericLiteral", "DoubleStringCharacter", 
    "SingleStringCharacter", "EscapeSequence", "CharacterEscapeSequence", 
    "HexEscapeSequence", "UnicodeEscapeSequence", "SingleEscapeCharacter", 
    "NonEscapeCharacter", "EscapeCharacter", "DecimalDigit", "HexDigit", 
    "DecimalLiteral", "HexIntegerLiteral", "ExponentPart", "IdentifierStart", 
    "IdentifierPart", "UnicodeLetter", "UnicodeDigit", "UnicodeConnectorPunctuation", 
    "UnicodeCombiningMark", "Comment", "LineComment", "WhiteSpace", "'function'", 
    "'('", "','", "')'", "'{'", "'}'", "'var'", "';'", "'='", "'if'", "'else'", 
    "'do'", "'while'", "'for'", "'in'", "'continue'", "'break'", "'return'", 
    "'with'", "':'", "'switch'", "'case'", "'default'", "'throw'", "'try'", 
    "'catch'", "'finally'", "'new'", "'['", "']'", "'.'", "'*='", "'/='", 
    "'%='", "'+='", "'-='", "'<<='", "'>>='", "'>>>='", "'&='", "'^='", 
    "'|='", "'?'", "'||'", "'&&'", "'|'", "'^'", "'&'", "'=='", "'!='", 
    "'==='", "'!=='", "'<'", "'>'", "'<='", "'>='", "'instanceof'", "'<<'", 
    "'>>'", "'>>>'", "'+'", "'-'", "'*'", "'/'", "'%'", "'delete'", "'void'", 
    "'typeof'", "'++'", "'--'", "'~'", "'!'", "'this'", "'null'", "'true'", 
    "'false'"
]




class JavaScriptParser(Parser):
    grammarFileName = "/home/buffer/antlr/JavaScript.g"
    antlr_version = version_str_to_tuple("3.1.3 October 14, 2010 12:41:46")
    antlr_version_str = "3.1.3 October 14, 2010 12:41:46"
    tokenNames = tokenNames

    def __init__(self, input, state=None, *args, **kwargs):
        if state is None:
            state = RecognizerSharedState()

        super(JavaScriptParser, self).__init__(input, state, *args, **kwargs)

        self._state.ruleMemo = {}
        self.dfa4 = self.DFA4(
            self, 4,
            eot = self.DFA4_eot,
            eof = self.DFA4_eof,
            min = self.DFA4_min,
            max = self.DFA4_max,
            accept = self.DFA4_accept,
            special = self.DFA4_special,
            transition = self.DFA4_transition
            )

        self.dfa5 = self.DFA5(
            self, 5,
            eot = self.DFA5_eot,
            eof = self.DFA5_eof,
            min = self.DFA5_min,
            max = self.DFA5_max,
            accept = self.DFA5_accept,
            special = self.DFA5_special,
            transition = self.DFA5_transition
            )

        self.dfa17 = self.DFA17(
            self, 17,
            eot = self.DFA17_eot,
            eof = self.DFA17_eof,
            min = self.DFA17_min,
            max = self.DFA17_max,
            accept = self.DFA17_accept,
            special = self.DFA17_special,
            transition = self.DFA17_transition
            )

        self.dfa16 = self.DFA16(
            self, 16,
            eot = self.DFA16_eot,
            eof = self.DFA16_eof,
            min = self.DFA16_min,
            max = self.DFA16_max,
            accept = self.DFA16_accept,
            special = self.DFA16_special,
            transition = self.DFA16_transition
            )

        self.dfa21 = self.DFA21(
            self, 21,
            eot = self.DFA21_eot,
            eof = self.DFA21_eof,
            min = self.DFA21_min,
            max = self.DFA21_max,
            accept = self.DFA21_accept,
            special = self.DFA21_special,
            transition = self.DFA21_transition
            )

        self.dfa26 = self.DFA26(
            self, 26,
            eot = self.DFA26_eot,
            eof = self.DFA26_eof,
            min = self.DFA26_min,
            max = self.DFA26_max,
            accept = self.DFA26_accept,
            special = self.DFA26_special,
            transition = self.DFA26_transition
            )

        self.dfa30 = self.DFA30(
            self, 30,
            eot = self.DFA30_eot,
            eof = self.DFA30_eof,
            min = self.DFA30_min,
            max = self.DFA30_max,
            accept = self.DFA30_accept,
            special = self.DFA30_special,
            transition = self.DFA30_transition
            )

        self.dfa33 = self.DFA33(
            self, 33,
            eot = self.DFA33_eot,
            eof = self.DFA33_eof,
            min = self.DFA33_min,
            max = self.DFA33_max,
            accept = self.DFA33_accept,
            special = self.DFA33_special,
            transition = self.DFA33_transition
            )

        self.dfa57 = self.DFA57(
            self, 57,
            eot = self.DFA57_eot,
            eof = self.DFA57_eof,
            min = self.DFA57_min,
            max = self.DFA57_max,
            accept = self.DFA57_accept,
            special = self.DFA57_special,
            transition = self.DFA57_transition
            )

        self.dfa60 = self.DFA60(
            self, 60,
            eot = self.DFA60_eot,
            eof = self.DFA60_eof,
            min = self.DFA60_min,
            max = self.DFA60_max,
            accept = self.DFA60_accept,
            special = self.DFA60_special,
            transition = self.DFA60_transition
            )

        self.dfa63 = self.DFA63(
            self, 63,
            eot = self.DFA63_eot,
            eof = self.DFA63_eof,
            min = self.DFA63_min,
            max = self.DFA63_max,
            accept = self.DFA63_accept,
            special = self.DFA63_special,
            transition = self.DFA63_transition
            )

        self.dfa90 = self.DFA90(
            self, 90,
            eot = self.DFA90_eot,
            eof = self.DFA90_eof,
            min = self.DFA90_min,
            max = self.DFA90_max,
            accept = self.DFA90_accept,
            special = self.DFA90_special,
            transition = self.DFA90_transition
            )

        self.dfa94 = self.DFA94(
            self, 94,
            eot = self.DFA94_eot,
            eof = self.DFA94_eof,
            min = self.DFA94_min,
            max = self.DFA94_max,
            accept = self.DFA94_accept,
            special = self.DFA94_special,
            transition = self.DFA94_transition
            )

        self.dfa93 = self.DFA93(
            self, 93,
            eot = self.DFA93_eot,
            eof = self.DFA93_eof,
            min = self.DFA93_min,
            max = self.DFA93_max,
            accept = self.DFA93_accept,
            special = self.DFA93_special,
            transition = self.DFA93_transition
            )

        self.dfa106 = self.DFA106(
            self, 106,
            eot = self.DFA106_eot,
            eof = self.DFA106_eof,
            min = self.DFA106_min,
            max = self.DFA106_max,
            accept = self.DFA106_accept,
            special = self.DFA106_special,
            transition = self.DFA106_transition
            )

        self.dfa115 = self.DFA115(
            self, 115,
            eot = self.DFA115_eot,
            eof = self.DFA115_eof,
            min = self.DFA115_min,
            max = self.DFA115_max,
            accept = self.DFA115_accept,
            special = self.DFA115_special,
            transition = self.DFA115_transition
            )

        self.dfa118 = self.DFA118(
            self, 118,
            eot = self.DFA118_eot,
            eof = self.DFA118_eof,
            min = self.DFA118_min,
            max = self.DFA118_max,
            accept = self.DFA118_accept,
            special = self.DFA118_special,
            transition = self.DFA118_transition
            )

        self.dfa121 = self.DFA121(
            self, 121,
            eot = self.DFA121_eot,
            eof = self.DFA121_eof,
            min = self.DFA121_min,
            max = self.DFA121_max,
            accept = self.DFA121_accept,
            special = self.DFA121_special,
            transition = self.DFA121_transition
            )

        self.dfa124 = self.DFA124(
            self, 124,
            eot = self.DFA124_eot,
            eof = self.DFA124_eof,
            min = self.DFA124_min,
            max = self.DFA124_max,
            accept = self.DFA124_accept,
            special = self.DFA124_special,
            transition = self.DFA124_transition
            )

        self.dfa125 = self.DFA125(
            self, 125,
            eot = self.DFA125_eot,
            eof = self.DFA125_eof,
            min = self.DFA125_min,
            max = self.DFA125_max,
            accept = self.DFA125_accept,
            special = self.DFA125_special,
            transition = self.DFA125_transition
            )

        self.dfa127 = self.DFA127(
            self, 127,
            eot = self.DFA127_eot,
            eof = self.DFA127_eof,
            min = self.DFA127_min,
            max = self.DFA127_max,
            accept = self.DFA127_accept,
            special = self.DFA127_special,
            transition = self.DFA127_transition
            )

        self.dfa132 = self.DFA132(
            self, 132,
            eot = self.DFA132_eot,
            eof = self.DFA132_eof,
            min = self.DFA132_min,
            max = self.DFA132_max,
            accept = self.DFA132_accept,
            special = self.DFA132_special,
            transition = self.DFA132_transition
            )

        self.dfa136 = self.DFA136(
            self, 136,
            eot = self.DFA136_eot,
            eof = self.DFA136_eof,
            min = self.DFA136_min,
            max = self.DFA136_max,
            accept = self.DFA136_accept,
            special = self.DFA136_special,
            transition = self.DFA136_transition
            )

        self.dfa142 = self.DFA142(
            self, 142,
            eot = self.DFA142_eot,
            eof = self.DFA142_eof,
            min = self.DFA142_min,
            max = self.DFA142_max,
            accept = self.DFA142_accept,
            special = self.DFA142_special,
            transition = self.DFA142_transition
            )

        self.dfa141 = self.DFA141(
            self, 141,
            eot = self.DFA141_eot,
            eof = self.DFA141_eof,
            min = self.DFA141_min,
            max = self.DFA141_max,
            accept = self.DFA141_accept,
            special = self.DFA141_special,
            transition = self.DFA141_transition
            )

        self.dfa151 = self.DFA151(
            self, 151,
            eot = self.DFA151_eot,
            eof = self.DFA151_eof,
            min = self.DFA151_min,
            max = self.DFA151_max,
            accept = self.DFA151_accept,
            special = self.DFA151_special,
            transition = self.DFA151_transition
            )

        self.dfa156 = self.DFA156(
            self, 156,
            eot = self.DFA156_eot,
            eof = self.DFA156_eof,
            min = self.DFA156_min,
            max = self.DFA156_max,
            accept = self.DFA156_accept,
            special = self.DFA156_special,
            transition = self.DFA156_transition
            )

        self.dfa159 = self.DFA159(
            self, 159,
            eot = self.DFA159_eot,
            eof = self.DFA159_eof,
            min = self.DFA159_min,
            max = self.DFA159_max,
            accept = self.DFA159_accept,
            special = self.DFA159_special,
            transition = self.DFA159_transition
            )

        self.dfa162 = self.DFA162(
            self, 162,
            eot = self.DFA162_eot,
            eof = self.DFA162_eof,
            min = self.DFA162_min,
            max = self.DFA162_max,
            accept = self.DFA162_accept,
            special = self.DFA162_special,
            transition = self.DFA162_transition
            )

        self.dfa165 = self.DFA165(
            self, 165,
            eot = self.DFA165_eot,
            eof = self.DFA165_eof,
            min = self.DFA165_min,
            max = self.DFA165_max,
            accept = self.DFA165_accept,
            special = self.DFA165_special,
            transition = self.DFA165_transition
            )

        self.dfa168 = self.DFA168(
            self, 168,
            eot = self.DFA168_eot,
            eof = self.DFA168_eof,
            min = self.DFA168_min,
            max = self.DFA168_max,
            accept = self.DFA168_accept,
            special = self.DFA168_special,
            transition = self.DFA168_transition
            )

        self.dfa171 = self.DFA171(
            self, 171,
            eot = self.DFA171_eot,
            eof = self.DFA171_eof,
            min = self.DFA171_min,
            max = self.DFA171_max,
            accept = self.DFA171_accept,
            special = self.DFA171_special,
            transition = self.DFA171_transition
            )

        self.dfa174 = self.DFA174(
            self, 174,
            eot = self.DFA174_eot,
            eof = self.DFA174_eof,
            min = self.DFA174_min,
            max = self.DFA174_max,
            accept = self.DFA174_accept,
            special = self.DFA174_special,
            transition = self.DFA174_transition
            )

        self.dfa177 = self.DFA177(
            self, 177,
            eot = self.DFA177_eot,
            eof = self.DFA177_eof,
            min = self.DFA177_min,
            max = self.DFA177_max,
            accept = self.DFA177_accept,
            special = self.DFA177_special,
            transition = self.DFA177_transition
            )

        self.dfa180 = self.DFA180(
            self, 180,
            eot = self.DFA180_eot,
            eof = self.DFA180_eof,
            min = self.DFA180_min,
            max = self.DFA180_max,
            accept = self.DFA180_accept,
            special = self.DFA180_special,
            transition = self.DFA180_transition
            )

        self.dfa183 = self.DFA183(
            self, 183,
            eot = self.DFA183_eot,
            eof = self.DFA183_eof,
            min = self.DFA183_min,
            max = self.DFA183_max,
            accept = self.DFA183_accept,
            special = self.DFA183_special,
            transition = self.DFA183_transition
            )

        self.dfa186 = self.DFA186(
            self, 186,
            eot = self.DFA186_eot,
            eof = self.DFA186_eof,
            min = self.DFA186_min,
            max = self.DFA186_max,
            accept = self.DFA186_accept,
            special = self.DFA186_special,
            transition = self.DFA186_transition
            )

        self.dfa189 = self.DFA189(
            self, 189,
            eot = self.DFA189_eot,
            eof = self.DFA189_eof,
            min = self.DFA189_min,
            max = self.DFA189_max,
            accept = self.DFA189_accept,
            special = self.DFA189_special,
            transition = self.DFA189_transition
            )

        self.dfa192 = self.DFA192(
            self, 192,
            eot = self.DFA192_eot,
            eof = self.DFA192_eof,
            min = self.DFA192_min,
            max = self.DFA192_max,
            accept = self.DFA192_accept,
            special = self.DFA192_special,
            transition = self.DFA192_transition
            )

        self.dfa195 = self.DFA195(
            self, 195,
            eot = self.DFA195_eot,
            eof = self.DFA195_eof,
            min = self.DFA195_min,
            max = self.DFA195_max,
            accept = self.DFA195_accept,
            special = self.DFA195_special,
            transition = self.DFA195_transition
            )

        self.dfa198 = self.DFA198(
            self, 198,
            eot = self.DFA198_eot,
            eof = self.DFA198_eof,
            min = self.DFA198_min,
            max = self.DFA198_max,
            accept = self.DFA198_accept,
            special = self.DFA198_special,
            transition = self.DFA198_transition
            )

        self.dfa201 = self.DFA201(
            self, 201,
            eot = self.DFA201_eot,
            eof = self.DFA201_eof,
            min = self.DFA201_min,
            max = self.DFA201_max,
            accept = self.DFA201_accept,
            special = self.DFA201_special,
            transition = self.DFA201_transition
            )

        self.dfa204 = self.DFA204(
            self, 204,
            eot = self.DFA204_eot,
            eof = self.DFA204_eof,
            min = self.DFA204_min,
            max = self.DFA204_max,
            accept = self.DFA204_accept,
            special = self.DFA204_special,
            transition = self.DFA204_transition
            )

        self.dfa207 = self.DFA207(
            self, 207,
            eot = self.DFA207_eot,
            eof = self.DFA207_eof,
            min = self.DFA207_min,
            max = self.DFA207_max,
            accept = self.DFA207_accept,
            special = self.DFA207_special,
            transition = self.DFA207_transition
            )

        self.dfa218 = self.DFA218(
            self, 218,
            eot = self.DFA218_eot,
            eof = self.DFA218_eof,
            min = self.DFA218_min,
            max = self.DFA218_max,
            accept = self.DFA218_accept,
            special = self.DFA218_special,
            transition = self.DFA218_transition
            )

        self.dfa217 = self.DFA217(
            self, 217,
            eot = self.DFA217_eot,
            eof = self.DFA217_eof,
            min = self.DFA217_min,
            max = self.DFA217_max,
            accept = self.DFA217_accept,
            special = self.DFA217_special,
            transition = self.DFA217_transition
            )

        self.dfa223 = self.DFA223(
            self, 223,
            eot = self.DFA223_eot,
            eof = self.DFA223_eof,
            min = self.DFA223_min,
            max = self.DFA223_max,
            accept = self.DFA223_accept,
            special = self.DFA223_special,
            transition = self.DFA223_transition
            )






        self._adaptor = None
        self.adaptor = CommonTreeAdaptor()
                


        
    def getTreeAdaptor(self):
        return self._adaptor

    def setTreeAdaptor(self, adaptor):
        self._adaptor = adaptor

    adaptor = property(getTreeAdaptor, setTreeAdaptor)


    class program_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.program_return, self).__init__()

            self.tree = None




    # $ANTLR start "program"
    # /home/buffer/antlr/JavaScript.g:16:1: program : ( LT )* sourceElements ( LT )* EOF ;
    def program(self, ):

        retval = self.program_return()
        retval.start = self.input.LT(1)
        program_StartIndex = self.input.index()
        root_0 = None

        LT1 = None
        LT3 = None
        EOF4 = None
        sourceElements2 = None


        LT1_tree = None
        LT3_tree = None
        EOF4_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 1):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:17:2: ( ( LT )* sourceElements ( LT )* EOF )
                # /home/buffer/antlr/JavaScript.g:17:4: ( LT )* sourceElements ( LT )* EOF
                pass 
                root_0 = self._adaptor.nil()

                # /home/buffer/antlr/JavaScript.g:17:6: ( LT )*
                while True: #loop1
                    alt1 = 2
                    LA1_0 = self.input.LA(1)

                    if (LA1_0 == LT) :
                        alt1 = 1


                    if alt1 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT1=self.match(self.input, LT, self.FOLLOW_LT_in_program43)


                    else:
                        break #loop1
                self._state.following.append(self.FOLLOW_sourceElements_in_program47)
                sourceElements2 = self.sourceElements()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, sourceElements2.tree)
                # /home/buffer/antlr/JavaScript.g:17:26: ( LT )*
                while True: #loop2
                    alt2 = 2
                    LA2_0 = self.input.LA(1)

                    if (LA2_0 == LT) :
                        alt2 = 1


                    if alt2 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT3=self.match(self.input, LT, self.FOLLOW_LT_in_program49)


                    else:
                        break #loop2
                EOF4=self.match(self.input, EOF, self.FOLLOW_EOF_in_program53)



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 1, program_StartIndex, success)

            pass
        return retval

    # $ANTLR end "program"

    class sourceElements_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.sourceElements_return, self).__init__()

            self.tree = None




    # $ANTLR start "sourceElements"
    # /home/buffer/antlr/JavaScript.g:20:1: sourceElements : sourceElement ( ( LT )* sourceElement )* ;
    def sourceElements(self, ):

        retval = self.sourceElements_return()
        retval.start = self.input.LT(1)
        sourceElements_StartIndex = self.input.index()
        root_0 = None

        LT6 = None
        sourceElement5 = None

        sourceElement7 = None


        LT6_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 2):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:21:2: ( sourceElement ( ( LT )* sourceElement )* )
                # /home/buffer/antlr/JavaScript.g:21:4: sourceElement ( ( LT )* sourceElement )*
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_sourceElement_in_sourceElements66)
                sourceElement5 = self.sourceElement()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, sourceElement5.tree)
                # /home/buffer/antlr/JavaScript.g:21:18: ( ( LT )* sourceElement )*
                while True: #loop4
                    alt4 = 2
                    alt4 = self.dfa4.predict(self.input)
                    if alt4 == 1:
                        # /home/buffer/antlr/JavaScript.g:21:19: ( LT )* sourceElement
                        pass 
                        # /home/buffer/antlr/JavaScript.g:21:21: ( LT )*
                        while True: #loop3
                            alt3 = 2
                            LA3_0 = self.input.LA(1)

                            if (LA3_0 == LT) :
                                alt3 = 1


                            if alt3 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT6=self.match(self.input, LT, self.FOLLOW_LT_in_sourceElements69)


                            else:
                                break #loop3
                        self._state.following.append(self.FOLLOW_sourceElement_in_sourceElements73)
                        sourceElement7 = self.sourceElement()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, sourceElement7.tree)


                    else:
                        break #loop4



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 2, sourceElements_StartIndex, success)

            pass
        return retval

    # $ANTLR end "sourceElements"

    class sourceElement_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.sourceElement_return, self).__init__()

            self.tree = None




    # $ANTLR start "sourceElement"
    # /home/buffer/antlr/JavaScript.g:24:1: sourceElement : ( functionDeclaration | statement );
    def sourceElement(self, ):

        retval = self.sourceElement_return()
        retval.start = self.input.LT(1)
        sourceElement_StartIndex = self.input.index()
        root_0 = None

        functionDeclaration8 = None

        statement9 = None



        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 3):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:25:2: ( functionDeclaration | statement )
                alt5 = 2
                alt5 = self.dfa5.predict(self.input)
                if alt5 == 1:
                    # /home/buffer/antlr/JavaScript.g:25:4: functionDeclaration
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_functionDeclaration_in_sourceElement87)
                    functionDeclaration8 = self.functionDeclaration()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, functionDeclaration8.tree)


                elif alt5 == 2:
                    # /home/buffer/antlr/JavaScript.g:26:4: statement
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_statement_in_sourceElement92)
                    statement9 = self.statement()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, statement9.tree)


                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 3, sourceElement_StartIndex, success)

            pass
        return retval

    # $ANTLR end "sourceElement"

    class functionDeclaration_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.functionDeclaration_return, self).__init__()

            self.tree = None




    # $ANTLR start "functionDeclaration"
    # /home/buffer/antlr/JavaScript.g:30:1: functionDeclaration : 'function' ( LT )* Identifier ( LT )* formalParameterList ( LT )* functionBody ;
    def functionDeclaration(self, ):

        retval = self.functionDeclaration_return()
        retval.start = self.input.LT(1)
        functionDeclaration_StartIndex = self.input.index()
        root_0 = None

        string_literal10 = None
        LT11 = None
        Identifier12 = None
        LT13 = None
        LT15 = None
        formalParameterList14 = None

        functionBody16 = None


        string_literal10_tree = None
        LT11_tree = None
        Identifier12_tree = None
        LT13_tree = None
        LT15_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 4):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:31:2: ( 'function' ( LT )* Identifier ( LT )* formalParameterList ( LT )* functionBody )
                # /home/buffer/antlr/JavaScript.g:31:4: 'function' ( LT )* Identifier ( LT )* formalParameterList ( LT )* functionBody
                pass 
                root_0 = self._adaptor.nil()

                string_literal10=self.match(self.input, 31, self.FOLLOW_31_in_functionDeclaration105)
                if self._state.backtracking == 0:

                    string_literal10_tree = self._adaptor.createWithPayload(string_literal10)
                    self._adaptor.addChild(root_0, string_literal10_tree)

                # /home/buffer/antlr/JavaScript.g:31:17: ( LT )*
                while True: #loop6
                    alt6 = 2
                    LA6_0 = self.input.LA(1)

                    if (LA6_0 == LT) :
                        alt6 = 1


                    if alt6 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT11=self.match(self.input, LT, self.FOLLOW_LT_in_functionDeclaration107)


                    else:
                        break #loop6
                Identifier12=self.match(self.input, Identifier, self.FOLLOW_Identifier_in_functionDeclaration111)
                if self._state.backtracking == 0:

                    Identifier12_tree = self._adaptor.createWithPayload(Identifier12)
                    self._adaptor.addChild(root_0, Identifier12_tree)

                # /home/buffer/antlr/JavaScript.g:31:33: ( LT )*
                while True: #loop7
                    alt7 = 2
                    LA7_0 = self.input.LA(1)

                    if (LA7_0 == LT) :
                        alt7 = 1


                    if alt7 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT13=self.match(self.input, LT, self.FOLLOW_LT_in_functionDeclaration113)


                    else:
                        break #loop7
                self._state.following.append(self.FOLLOW_formalParameterList_in_functionDeclaration117)
                formalParameterList14 = self.formalParameterList()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, formalParameterList14.tree)
                # /home/buffer/antlr/JavaScript.g:31:58: ( LT )*
                while True: #loop8
                    alt8 = 2
                    LA8_0 = self.input.LA(1)

                    if (LA8_0 == LT) :
                        alt8 = 1


                    if alt8 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT15=self.match(self.input, LT, self.FOLLOW_LT_in_functionDeclaration119)


                    else:
                        break #loop8
                self._state.following.append(self.FOLLOW_functionBody_in_functionDeclaration123)
                functionBody16 = self.functionBody()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, functionBody16.tree)



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 4, functionDeclaration_StartIndex, success)

            pass
        return retval

    # $ANTLR end "functionDeclaration"

    class functionExpression_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.functionExpression_return, self).__init__()

            self.tree = None




    # $ANTLR start "functionExpression"
    # /home/buffer/antlr/JavaScript.g:34:1: functionExpression : 'function' ( LT )* ( Identifier )? ( LT )* formalParameterList ( LT )* functionBody ;
    def functionExpression(self, ):

        retval = self.functionExpression_return()
        retval.start = self.input.LT(1)
        functionExpression_StartIndex = self.input.index()
        root_0 = None

        string_literal17 = None
        LT18 = None
        Identifier19 = None
        LT20 = None
        LT22 = None
        formalParameterList21 = None

        functionBody23 = None


        string_literal17_tree = None
        LT18_tree = None
        Identifier19_tree = None
        LT20_tree = None
        LT22_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 5):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:35:2: ( 'function' ( LT )* ( Identifier )? ( LT )* formalParameterList ( LT )* functionBody )
                # /home/buffer/antlr/JavaScript.g:35:4: 'function' ( LT )* ( Identifier )? ( LT )* formalParameterList ( LT )* functionBody
                pass 
                root_0 = self._adaptor.nil()

                string_literal17=self.match(self.input, 31, self.FOLLOW_31_in_functionExpression135)
                if self._state.backtracking == 0:

                    string_literal17_tree = self._adaptor.createWithPayload(string_literal17)
                    self._adaptor.addChild(root_0, string_literal17_tree)

                # /home/buffer/antlr/JavaScript.g:35:17: ( LT )*
                while True: #loop9
                    alt9 = 2
                    LA9_0 = self.input.LA(1)

                    if (LA9_0 == LT) :
                        LA9_2 = self.input.LA(2)

                        if (self.synpred9_JavaScript()) :
                            alt9 = 1




                    if alt9 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT18=self.match(self.input, LT, self.FOLLOW_LT_in_functionExpression137)


                    else:
                        break #loop9
                # /home/buffer/antlr/JavaScript.g:35:20: ( Identifier )?
                alt10 = 2
                LA10_0 = self.input.LA(1)

                if (LA10_0 == Identifier) :
                    alt10 = 1
                if alt10 == 1:
                    # /home/buffer/antlr/JavaScript.g:0:0: Identifier
                    pass 
                    Identifier19=self.match(self.input, Identifier, self.FOLLOW_Identifier_in_functionExpression141)
                    if self._state.backtracking == 0:

                        Identifier19_tree = self._adaptor.createWithPayload(Identifier19)
                        self._adaptor.addChild(root_0, Identifier19_tree)




                # /home/buffer/antlr/JavaScript.g:35:34: ( LT )*
                while True: #loop11
                    alt11 = 2
                    LA11_0 = self.input.LA(1)

                    if (LA11_0 == LT) :
                        alt11 = 1


                    if alt11 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT20=self.match(self.input, LT, self.FOLLOW_LT_in_functionExpression144)


                    else:
                        break #loop11
                self._state.following.append(self.FOLLOW_formalParameterList_in_functionExpression148)
                formalParameterList21 = self.formalParameterList()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, formalParameterList21.tree)
                # /home/buffer/antlr/JavaScript.g:35:59: ( LT )*
                while True: #loop12
                    alt12 = 2
                    LA12_0 = self.input.LA(1)

                    if (LA12_0 == LT) :
                        alt12 = 1


                    if alt12 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT22=self.match(self.input, LT, self.FOLLOW_LT_in_functionExpression150)


                    else:
                        break #loop12
                self._state.following.append(self.FOLLOW_functionBody_in_functionExpression154)
                functionBody23 = self.functionBody()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, functionBody23.tree)



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 5, functionExpression_StartIndex, success)

            pass
        return retval

    # $ANTLR end "functionExpression"

    class formalParameterList_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.formalParameterList_return, self).__init__()

            self.tree = None




    # $ANTLR start "formalParameterList"
    # /home/buffer/antlr/JavaScript.g:38:1: formalParameterList : '(' ( ( LT )* Identifier ( ( LT )* ',' ( LT )* Identifier )* )? ( LT )* ')' ;
    def formalParameterList(self, ):

        retval = self.formalParameterList_return()
        retval.start = self.input.LT(1)
        formalParameterList_StartIndex = self.input.index()
        root_0 = None

        char_literal24 = None
        LT25 = None
        Identifier26 = None
        LT27 = None
        char_literal28 = None
        LT29 = None
        Identifier30 = None
        LT31 = None
        char_literal32 = None

        char_literal24_tree = None
        LT25_tree = None
        Identifier26_tree = None
        LT27_tree = None
        char_literal28_tree = None
        LT29_tree = None
        Identifier30_tree = None
        LT31_tree = None
        char_literal32_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 6):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:39:2: ( '(' ( ( LT )* Identifier ( ( LT )* ',' ( LT )* Identifier )* )? ( LT )* ')' )
                # /home/buffer/antlr/JavaScript.g:39:4: '(' ( ( LT )* Identifier ( ( LT )* ',' ( LT )* Identifier )* )? ( LT )* ')'
                pass 
                root_0 = self._adaptor.nil()

                char_literal24=self.match(self.input, 32, self.FOLLOW_32_in_formalParameterList166)
                if self._state.backtracking == 0:

                    char_literal24_tree = self._adaptor.createWithPayload(char_literal24)
                    self._adaptor.addChild(root_0, char_literal24_tree)

                # /home/buffer/antlr/JavaScript.g:39:8: ( ( LT )* Identifier ( ( LT )* ',' ( LT )* Identifier )* )?
                alt17 = 2
                alt17 = self.dfa17.predict(self.input)
                if alt17 == 1:
                    # /home/buffer/antlr/JavaScript.g:39:9: ( LT )* Identifier ( ( LT )* ',' ( LT )* Identifier )*
                    pass 
                    # /home/buffer/antlr/JavaScript.g:39:11: ( LT )*
                    while True: #loop13
                        alt13 = 2
                        LA13_0 = self.input.LA(1)

                        if (LA13_0 == LT) :
                            alt13 = 1


                        if alt13 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT25=self.match(self.input, LT, self.FOLLOW_LT_in_formalParameterList169)


                        else:
                            break #loop13
                    Identifier26=self.match(self.input, Identifier, self.FOLLOW_Identifier_in_formalParameterList173)
                    if self._state.backtracking == 0:

                        Identifier26_tree = self._adaptor.createWithPayload(Identifier26)
                        self._adaptor.addChild(root_0, Identifier26_tree)

                    # /home/buffer/antlr/JavaScript.g:39:25: ( ( LT )* ',' ( LT )* Identifier )*
                    while True: #loop16
                        alt16 = 2
                        alt16 = self.dfa16.predict(self.input)
                        if alt16 == 1:
                            # /home/buffer/antlr/JavaScript.g:39:26: ( LT )* ',' ( LT )* Identifier
                            pass 
                            # /home/buffer/antlr/JavaScript.g:39:28: ( LT )*
                            while True: #loop14
                                alt14 = 2
                                LA14_0 = self.input.LA(1)

                                if (LA14_0 == LT) :
                                    alt14 = 1


                                if alt14 == 1:
                                    # /home/buffer/antlr/JavaScript.g:0:0: LT
                                    pass 
                                    LT27=self.match(self.input, LT, self.FOLLOW_LT_in_formalParameterList176)


                                else:
                                    break #loop14
                            char_literal28=self.match(self.input, 33, self.FOLLOW_33_in_formalParameterList180)
                            if self._state.backtracking == 0:

                                char_literal28_tree = self._adaptor.createWithPayload(char_literal28)
                                self._adaptor.addChild(root_0, char_literal28_tree)

                            # /home/buffer/antlr/JavaScript.g:39:37: ( LT )*
                            while True: #loop15
                                alt15 = 2
                                LA15_0 = self.input.LA(1)

                                if (LA15_0 == LT) :
                                    alt15 = 1


                                if alt15 == 1:
                                    # /home/buffer/antlr/JavaScript.g:0:0: LT
                                    pass 
                                    LT29=self.match(self.input, LT, self.FOLLOW_LT_in_formalParameterList182)


                                else:
                                    break #loop15
                            Identifier30=self.match(self.input, Identifier, self.FOLLOW_Identifier_in_formalParameterList186)
                            if self._state.backtracking == 0:

                                Identifier30_tree = self._adaptor.createWithPayload(Identifier30)
                                self._adaptor.addChild(root_0, Identifier30_tree)



                        else:
                            break #loop16



                # /home/buffer/antlr/JavaScript.g:39:57: ( LT )*
                while True: #loop18
                    alt18 = 2
                    LA18_0 = self.input.LA(1)

                    if (LA18_0 == LT) :
                        alt18 = 1


                    if alt18 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT31=self.match(self.input, LT, self.FOLLOW_LT_in_formalParameterList192)


                    else:
                        break #loop18
                char_literal32=self.match(self.input, 34, self.FOLLOW_34_in_formalParameterList196)
                if self._state.backtracking == 0:

                    char_literal32_tree = self._adaptor.createWithPayload(char_literal32)
                    self._adaptor.addChild(root_0, char_literal32_tree)




                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 6, formalParameterList_StartIndex, success)

            pass
        return retval

    # $ANTLR end "formalParameterList"

    class functionBody_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.functionBody_return, self).__init__()

            self.tree = None




    # $ANTLR start "functionBody"
    # /home/buffer/antlr/JavaScript.g:42:1: functionBody : '{' ( LT )* sourceElements ( LT )* '}' ;
    def functionBody(self, ):

        retval = self.functionBody_return()
        retval.start = self.input.LT(1)
        functionBody_StartIndex = self.input.index()
        root_0 = None

        char_literal33 = None
        LT34 = None
        LT36 = None
        char_literal37 = None
        sourceElements35 = None


        char_literal33_tree = None
        LT34_tree = None
        LT36_tree = None
        char_literal37_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 7):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:43:2: ( '{' ( LT )* sourceElements ( LT )* '}' )
                # /home/buffer/antlr/JavaScript.g:43:4: '{' ( LT )* sourceElements ( LT )* '}'
                pass 
                root_0 = self._adaptor.nil()

                char_literal33=self.match(self.input, 35, self.FOLLOW_35_in_functionBody207)
                if self._state.backtracking == 0:

                    char_literal33_tree = self._adaptor.createWithPayload(char_literal33)
                    self._adaptor.addChild(root_0, char_literal33_tree)

                # /home/buffer/antlr/JavaScript.g:43:10: ( LT )*
                while True: #loop19
                    alt19 = 2
                    LA19_0 = self.input.LA(1)

                    if (LA19_0 == LT) :
                        alt19 = 1


                    if alt19 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT34=self.match(self.input, LT, self.FOLLOW_LT_in_functionBody209)


                    else:
                        break #loop19
                self._state.following.append(self.FOLLOW_sourceElements_in_functionBody213)
                sourceElements35 = self.sourceElements()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, sourceElements35.tree)
                # /home/buffer/antlr/JavaScript.g:43:30: ( LT )*
                while True: #loop20
                    alt20 = 2
                    LA20_0 = self.input.LA(1)

                    if (LA20_0 == LT) :
                        alt20 = 1


                    if alt20 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT36=self.match(self.input, LT, self.FOLLOW_LT_in_functionBody215)


                    else:
                        break #loop20
                char_literal37=self.match(self.input, 36, self.FOLLOW_36_in_functionBody219)
                if self._state.backtracking == 0:

                    char_literal37_tree = self._adaptor.createWithPayload(char_literal37)
                    self._adaptor.addChild(root_0, char_literal37_tree)




                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 7, functionBody_StartIndex, success)

            pass
        return retval

    # $ANTLR end "functionBody"

    class statement_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.statement_return, self).__init__()

            self.tree = None




    # $ANTLR start "statement"
    # /home/buffer/antlr/JavaScript.g:47:1: statement : ( statementBlock | variableStatement | emptyStatement | expressionStatement | ifStatement | iterationStatement | continueStatement | breakStatement | returnStatement | withStatement | labelledStatement | switchStatement | throwStatement | tryStatement );
    def statement(self, ):

        retval = self.statement_return()
        retval.start = self.input.LT(1)
        statement_StartIndex = self.input.index()
        root_0 = None

        statementBlock38 = None

        variableStatement39 = None

        emptyStatement40 = None

        expressionStatement41 = None

        ifStatement42 = None

        iterationStatement43 = None

        continueStatement44 = None

        breakStatement45 = None

        returnStatement46 = None

        withStatement47 = None

        labelledStatement48 = None

        switchStatement49 = None

        throwStatement50 = None

        tryStatement51 = None



        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 8):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:48:2: ( statementBlock | variableStatement | emptyStatement | expressionStatement | ifStatement | iterationStatement | continueStatement | breakStatement | returnStatement | withStatement | labelledStatement | switchStatement | throwStatement | tryStatement )
                alt21 = 14
                alt21 = self.dfa21.predict(self.input)
                if alt21 == 1:
                    # /home/buffer/antlr/JavaScript.g:48:4: statementBlock
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_statementBlock_in_statement231)
                    statementBlock38 = self.statementBlock()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, statementBlock38.tree)


                elif alt21 == 2:
                    # /home/buffer/antlr/JavaScript.g:49:4: variableStatement
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_variableStatement_in_statement236)
                    variableStatement39 = self.variableStatement()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, variableStatement39.tree)


                elif alt21 == 3:
                    # /home/buffer/antlr/JavaScript.g:50:4: emptyStatement
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_emptyStatement_in_statement241)
                    emptyStatement40 = self.emptyStatement()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, emptyStatement40.tree)


                elif alt21 == 4:
                    # /home/buffer/antlr/JavaScript.g:51:4: expressionStatement
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_expressionStatement_in_statement246)
                    expressionStatement41 = self.expressionStatement()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, expressionStatement41.tree)


                elif alt21 == 5:
                    # /home/buffer/antlr/JavaScript.g:52:4: ifStatement
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_ifStatement_in_statement251)
                    ifStatement42 = self.ifStatement()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, ifStatement42.tree)


                elif alt21 == 6:
                    # /home/buffer/antlr/JavaScript.g:53:4: iterationStatement
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_iterationStatement_in_statement256)
                    iterationStatement43 = self.iterationStatement()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, iterationStatement43.tree)


                elif alt21 == 7:
                    # /home/buffer/antlr/JavaScript.g:54:4: continueStatement
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_continueStatement_in_statement261)
                    continueStatement44 = self.continueStatement()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, continueStatement44.tree)


                elif alt21 == 8:
                    # /home/buffer/antlr/JavaScript.g:55:4: breakStatement
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_breakStatement_in_statement266)
                    breakStatement45 = self.breakStatement()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, breakStatement45.tree)


                elif alt21 == 9:
                    # /home/buffer/antlr/JavaScript.g:56:4: returnStatement
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_returnStatement_in_statement271)
                    returnStatement46 = self.returnStatement()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, returnStatement46.tree)


                elif alt21 == 10:
                    # /home/buffer/antlr/JavaScript.g:57:4: withStatement
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_withStatement_in_statement276)
                    withStatement47 = self.withStatement()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, withStatement47.tree)


                elif alt21 == 11:
                    # /home/buffer/antlr/JavaScript.g:58:4: labelledStatement
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_labelledStatement_in_statement281)
                    labelledStatement48 = self.labelledStatement()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, labelledStatement48.tree)


                elif alt21 == 12:
                    # /home/buffer/antlr/JavaScript.g:59:4: switchStatement
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_switchStatement_in_statement286)
                    switchStatement49 = self.switchStatement()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, switchStatement49.tree)


                elif alt21 == 13:
                    # /home/buffer/antlr/JavaScript.g:60:4: throwStatement
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_throwStatement_in_statement291)
                    throwStatement50 = self.throwStatement()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, throwStatement50.tree)


                elif alt21 == 14:
                    # /home/buffer/antlr/JavaScript.g:61:4: tryStatement
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_tryStatement_in_statement296)
                    tryStatement51 = self.tryStatement()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, tryStatement51.tree)


                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 8, statement_StartIndex, success)

            pass
        return retval

    # $ANTLR end "statement"

    class statementBlock_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.statementBlock_return, self).__init__()

            self.tree = None




    # $ANTLR start "statementBlock"
    # /home/buffer/antlr/JavaScript.g:64:1: statementBlock : '{' ( LT )* ( statementList )? ( LT )* '}' ;
    def statementBlock(self, ):

        retval = self.statementBlock_return()
        retval.start = self.input.LT(1)
        statementBlock_StartIndex = self.input.index()
        root_0 = None

        char_literal52 = None
        LT53 = None
        LT55 = None
        char_literal56 = None
        statementList54 = None


        char_literal52_tree = None
        LT53_tree = None
        LT55_tree = None
        char_literal56_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 9):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:65:2: ( '{' ( LT )* ( statementList )? ( LT )* '}' )
                # /home/buffer/antlr/JavaScript.g:65:4: '{' ( LT )* ( statementList )? ( LT )* '}'
                pass 
                root_0 = self._adaptor.nil()

                char_literal52=self.match(self.input, 35, self.FOLLOW_35_in_statementBlock308)
                if self._state.backtracking == 0:

                    char_literal52_tree = self._adaptor.createWithPayload(char_literal52)
                    self._adaptor.addChild(root_0, char_literal52_tree)

                # /home/buffer/antlr/JavaScript.g:65:10: ( LT )*
                while True: #loop22
                    alt22 = 2
                    LA22_0 = self.input.LA(1)

                    if (LA22_0 == LT) :
                        LA22_2 = self.input.LA(2)

                        if (self.synpred34_JavaScript()) :
                            alt22 = 1




                    if alt22 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT53=self.match(self.input, LT, self.FOLLOW_LT_in_statementBlock310)


                    else:
                        break #loop22
                # /home/buffer/antlr/JavaScript.g:65:13: ( statementList )?
                alt23 = 2
                LA23_0 = self.input.LA(1)

                if ((Identifier <= LA23_0 <= NumericLiteral) or (31 <= LA23_0 <= 32) or LA23_0 == 35 or (37 <= LA23_0 <= 38) or LA23_0 == 40 or (42 <= LA23_0 <= 44) or (46 <= LA23_0 <= 49) or LA23_0 == 51 or (54 <= LA23_0 <= 55) or (58 <= LA23_0 <= 59) or (91 <= LA23_0 <= 92) or (96 <= LA23_0 <= 106)) :
                    alt23 = 1
                if alt23 == 1:
                    # /home/buffer/antlr/JavaScript.g:0:0: statementList
                    pass 
                    self._state.following.append(self.FOLLOW_statementList_in_statementBlock314)
                    statementList54 = self.statementList()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, statementList54.tree)



                # /home/buffer/antlr/JavaScript.g:65:30: ( LT )*
                while True: #loop24
                    alt24 = 2
                    LA24_0 = self.input.LA(1)

                    if (LA24_0 == LT) :
                        alt24 = 1


                    if alt24 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT55=self.match(self.input, LT, self.FOLLOW_LT_in_statementBlock317)


                    else:
                        break #loop24
                char_literal56=self.match(self.input, 36, self.FOLLOW_36_in_statementBlock321)
                if self._state.backtracking == 0:

                    char_literal56_tree = self._adaptor.createWithPayload(char_literal56)
                    self._adaptor.addChild(root_0, char_literal56_tree)




                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 9, statementBlock_StartIndex, success)

            pass
        return retval

    # $ANTLR end "statementBlock"

    class statementList_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.statementList_return, self).__init__()

            self.tree = None




    # $ANTLR start "statementList"
    # /home/buffer/antlr/JavaScript.g:68:1: statementList : statement ( ( LT )* statement )* ;
    def statementList(self, ):

        retval = self.statementList_return()
        retval.start = self.input.LT(1)
        statementList_StartIndex = self.input.index()
        root_0 = None

        LT58 = None
        statement57 = None

        statement59 = None


        LT58_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 10):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:69:2: ( statement ( ( LT )* statement )* )
                # /home/buffer/antlr/JavaScript.g:69:4: statement ( ( LT )* statement )*
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_statement_in_statementList333)
                statement57 = self.statement()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, statement57.tree)
                # /home/buffer/antlr/JavaScript.g:69:14: ( ( LT )* statement )*
                while True: #loop26
                    alt26 = 2
                    alt26 = self.dfa26.predict(self.input)
                    if alt26 == 1:
                        # /home/buffer/antlr/JavaScript.g:69:15: ( LT )* statement
                        pass 
                        # /home/buffer/antlr/JavaScript.g:69:17: ( LT )*
                        while True: #loop25
                            alt25 = 2
                            LA25_0 = self.input.LA(1)

                            if (LA25_0 == LT) :
                                alt25 = 1


                            if alt25 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT58=self.match(self.input, LT, self.FOLLOW_LT_in_statementList336)


                            else:
                                break #loop25
                        self._state.following.append(self.FOLLOW_statement_in_statementList340)
                        statement59 = self.statement()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, statement59.tree)


                    else:
                        break #loop26



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 10, statementList_StartIndex, success)

            pass
        return retval

    # $ANTLR end "statementList"

    class variableStatement_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.variableStatement_return, self).__init__()

            self.tree = None




    # $ANTLR start "variableStatement"
    # /home/buffer/antlr/JavaScript.g:72:1: variableStatement : 'var' ( LT )* variableDeclarationList ( LT | ';' ) ;
    def variableStatement(self, ):

        retval = self.variableStatement_return()
        retval.start = self.input.LT(1)
        variableStatement_StartIndex = self.input.index()
        root_0 = None

        string_literal60 = None
        LT61 = None
        set63 = None
        variableDeclarationList62 = None


        string_literal60_tree = None
        LT61_tree = None
        set63_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 11):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:73:2: ( 'var' ( LT )* variableDeclarationList ( LT | ';' ) )
                # /home/buffer/antlr/JavaScript.g:73:4: 'var' ( LT )* variableDeclarationList ( LT | ';' )
                pass 
                root_0 = self._adaptor.nil()

                string_literal60=self.match(self.input, 37, self.FOLLOW_37_in_variableStatement354)
                if self._state.backtracking == 0:

                    string_literal60_tree = self._adaptor.createWithPayload(string_literal60)
                    self._adaptor.addChild(root_0, string_literal60_tree)

                # /home/buffer/antlr/JavaScript.g:73:12: ( LT )*
                while True: #loop27
                    alt27 = 2
                    LA27_0 = self.input.LA(1)

                    if (LA27_0 == LT) :
                        alt27 = 1


                    if alt27 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT61=self.match(self.input, LT, self.FOLLOW_LT_in_variableStatement356)


                    else:
                        break #loop27
                self._state.following.append(self.FOLLOW_variableDeclarationList_in_variableStatement360)
                variableDeclarationList62 = self.variableDeclarationList()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, variableDeclarationList62.tree)
                set63 = self.input.LT(1)
                if self.input.LA(1) == LT or self.input.LA(1) == 38:
                    self.input.consume()
                    self._state.errorRecovery = False

                else:
                    if self._state.backtracking > 0:
                        raise BacktrackingFailed

                    mse = MismatchedSetException(None, self.input)
                    raise mse





                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 11, variableStatement_StartIndex, success)

            pass
        return retval

    # $ANTLR end "variableStatement"

    class variableDeclarationList_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.variableDeclarationList_return, self).__init__()

            self.tree = None




    # $ANTLR start "variableDeclarationList"
    # /home/buffer/antlr/JavaScript.g:76:1: variableDeclarationList : variableDeclaration ( ( LT )* ',' ( LT )* variableDeclaration )* ;
    def variableDeclarationList(self, ):

        retval = self.variableDeclarationList_return()
        retval.start = self.input.LT(1)
        variableDeclarationList_StartIndex = self.input.index()
        root_0 = None

        LT65 = None
        char_literal66 = None
        LT67 = None
        variableDeclaration64 = None

        variableDeclaration68 = None


        LT65_tree = None
        char_literal66_tree = None
        LT67_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 12):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:77:2: ( variableDeclaration ( ( LT )* ',' ( LT )* variableDeclaration )* )
                # /home/buffer/antlr/JavaScript.g:77:4: variableDeclaration ( ( LT )* ',' ( LT )* variableDeclaration )*
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_variableDeclaration_in_variableDeclarationList381)
                variableDeclaration64 = self.variableDeclaration()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, variableDeclaration64.tree)
                # /home/buffer/antlr/JavaScript.g:77:24: ( ( LT )* ',' ( LT )* variableDeclaration )*
                while True: #loop30
                    alt30 = 2
                    alt30 = self.dfa30.predict(self.input)
                    if alt30 == 1:
                        # /home/buffer/antlr/JavaScript.g:77:25: ( LT )* ',' ( LT )* variableDeclaration
                        pass 
                        # /home/buffer/antlr/JavaScript.g:77:27: ( LT )*
                        while True: #loop28
                            alt28 = 2
                            LA28_0 = self.input.LA(1)

                            if (LA28_0 == LT) :
                                alt28 = 1


                            if alt28 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT65=self.match(self.input, LT, self.FOLLOW_LT_in_variableDeclarationList384)


                            else:
                                break #loop28
                        char_literal66=self.match(self.input, 33, self.FOLLOW_33_in_variableDeclarationList388)
                        if self._state.backtracking == 0:

                            char_literal66_tree = self._adaptor.createWithPayload(char_literal66)
                            self._adaptor.addChild(root_0, char_literal66_tree)

                        # /home/buffer/antlr/JavaScript.g:77:36: ( LT )*
                        while True: #loop29
                            alt29 = 2
                            LA29_0 = self.input.LA(1)

                            if (LA29_0 == LT) :
                                alt29 = 1


                            if alt29 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT67=self.match(self.input, LT, self.FOLLOW_LT_in_variableDeclarationList390)


                            else:
                                break #loop29
                        self._state.following.append(self.FOLLOW_variableDeclaration_in_variableDeclarationList394)
                        variableDeclaration68 = self.variableDeclaration()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, variableDeclaration68.tree)


                    else:
                        break #loop30



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 12, variableDeclarationList_StartIndex, success)

            pass
        return retval

    # $ANTLR end "variableDeclarationList"

    class variableDeclarationListNoIn_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.variableDeclarationListNoIn_return, self).__init__()

            self.tree = None




    # $ANTLR start "variableDeclarationListNoIn"
    # /home/buffer/antlr/JavaScript.g:80:1: variableDeclarationListNoIn : variableDeclarationNoIn ( ( LT )* ',' ( LT )* variableDeclarationNoIn )* ;
    def variableDeclarationListNoIn(self, ):

        retval = self.variableDeclarationListNoIn_return()
        retval.start = self.input.LT(1)
        variableDeclarationListNoIn_StartIndex = self.input.index()
        root_0 = None

        LT70 = None
        char_literal71 = None
        LT72 = None
        variableDeclarationNoIn69 = None

        variableDeclarationNoIn73 = None


        LT70_tree = None
        char_literal71_tree = None
        LT72_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 13):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:81:2: ( variableDeclarationNoIn ( ( LT )* ',' ( LT )* variableDeclarationNoIn )* )
                # /home/buffer/antlr/JavaScript.g:81:4: variableDeclarationNoIn ( ( LT )* ',' ( LT )* variableDeclarationNoIn )*
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_variableDeclarationNoIn_in_variableDeclarationListNoIn408)
                variableDeclarationNoIn69 = self.variableDeclarationNoIn()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, variableDeclarationNoIn69.tree)
                # /home/buffer/antlr/JavaScript.g:81:28: ( ( LT )* ',' ( LT )* variableDeclarationNoIn )*
                while True: #loop33
                    alt33 = 2
                    alt33 = self.dfa33.predict(self.input)
                    if alt33 == 1:
                        # /home/buffer/antlr/JavaScript.g:81:29: ( LT )* ',' ( LT )* variableDeclarationNoIn
                        pass 
                        # /home/buffer/antlr/JavaScript.g:81:31: ( LT )*
                        while True: #loop31
                            alt31 = 2
                            LA31_0 = self.input.LA(1)

                            if (LA31_0 == LT) :
                                alt31 = 1


                            if alt31 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT70=self.match(self.input, LT, self.FOLLOW_LT_in_variableDeclarationListNoIn411)


                            else:
                                break #loop31
                        char_literal71=self.match(self.input, 33, self.FOLLOW_33_in_variableDeclarationListNoIn415)
                        if self._state.backtracking == 0:

                            char_literal71_tree = self._adaptor.createWithPayload(char_literal71)
                            self._adaptor.addChild(root_0, char_literal71_tree)

                        # /home/buffer/antlr/JavaScript.g:81:40: ( LT )*
                        while True: #loop32
                            alt32 = 2
                            LA32_0 = self.input.LA(1)

                            if (LA32_0 == LT) :
                                alt32 = 1


                            if alt32 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT72=self.match(self.input, LT, self.FOLLOW_LT_in_variableDeclarationListNoIn417)


                            else:
                                break #loop32
                        self._state.following.append(self.FOLLOW_variableDeclarationNoIn_in_variableDeclarationListNoIn421)
                        variableDeclarationNoIn73 = self.variableDeclarationNoIn()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, variableDeclarationNoIn73.tree)


                    else:
                        break #loop33



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 13, variableDeclarationListNoIn_StartIndex, success)

            pass
        return retval

    # $ANTLR end "variableDeclarationListNoIn"

    class variableDeclaration_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.variableDeclaration_return, self).__init__()

            self.tree = None




    # $ANTLR start "variableDeclaration"
    # /home/buffer/antlr/JavaScript.g:84:1: variableDeclaration : Identifier ( LT )* ( initialiser )? ;
    def variableDeclaration(self, ):

        retval = self.variableDeclaration_return()
        retval.start = self.input.LT(1)
        variableDeclaration_StartIndex = self.input.index()
        root_0 = None

        Identifier74 = None
        LT75 = None
        initialiser76 = None


        Identifier74_tree = None
        LT75_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 14):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:85:2: ( Identifier ( LT )* ( initialiser )? )
                # /home/buffer/antlr/JavaScript.g:85:4: Identifier ( LT )* ( initialiser )?
                pass 
                root_0 = self._adaptor.nil()

                Identifier74=self.match(self.input, Identifier, self.FOLLOW_Identifier_in_variableDeclaration435)
                if self._state.backtracking == 0:

                    Identifier74_tree = self._adaptor.createWithPayload(Identifier74)
                    self._adaptor.addChild(root_0, Identifier74_tree)

                # /home/buffer/antlr/JavaScript.g:85:17: ( LT )*
                while True: #loop34
                    alt34 = 2
                    LA34_0 = self.input.LA(1)

                    if (LA34_0 == LT) :
                        LA34_2 = self.input.LA(2)

                        if (self.synpred47_JavaScript()) :
                            alt34 = 1




                    if alt34 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT75=self.match(self.input, LT, self.FOLLOW_LT_in_variableDeclaration437)


                    else:
                        break #loop34
                # /home/buffer/antlr/JavaScript.g:85:20: ( initialiser )?
                alt35 = 2
                LA35_0 = self.input.LA(1)

                if (LA35_0 == 39) :
                    alt35 = 1
                if alt35 == 1:
                    # /home/buffer/antlr/JavaScript.g:0:0: initialiser
                    pass 
                    self._state.following.append(self.FOLLOW_initialiser_in_variableDeclaration441)
                    initialiser76 = self.initialiser()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, initialiser76.tree)






                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 14, variableDeclaration_StartIndex, success)

            pass
        return retval

    # $ANTLR end "variableDeclaration"

    class variableDeclarationNoIn_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.variableDeclarationNoIn_return, self).__init__()

            self.tree = None




    # $ANTLR start "variableDeclarationNoIn"
    # /home/buffer/antlr/JavaScript.g:88:1: variableDeclarationNoIn : Identifier ( LT )* ( initialiserNoIn )? ;
    def variableDeclarationNoIn(self, ):

        retval = self.variableDeclarationNoIn_return()
        retval.start = self.input.LT(1)
        variableDeclarationNoIn_StartIndex = self.input.index()
        root_0 = None

        Identifier77 = None
        LT78 = None
        initialiserNoIn79 = None


        Identifier77_tree = None
        LT78_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 15):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:89:2: ( Identifier ( LT )* ( initialiserNoIn )? )
                # /home/buffer/antlr/JavaScript.g:89:4: Identifier ( LT )* ( initialiserNoIn )?
                pass 
                root_0 = self._adaptor.nil()

                Identifier77=self.match(self.input, Identifier, self.FOLLOW_Identifier_in_variableDeclarationNoIn454)
                if self._state.backtracking == 0:

                    Identifier77_tree = self._adaptor.createWithPayload(Identifier77)
                    self._adaptor.addChild(root_0, Identifier77_tree)

                # /home/buffer/antlr/JavaScript.g:89:17: ( LT )*
                while True: #loop36
                    alt36 = 2
                    LA36_0 = self.input.LA(1)

                    if (LA36_0 == LT) :
                        LA36_2 = self.input.LA(2)

                        if (self.synpred49_JavaScript()) :
                            alt36 = 1




                    if alt36 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT78=self.match(self.input, LT, self.FOLLOW_LT_in_variableDeclarationNoIn456)


                    else:
                        break #loop36
                # /home/buffer/antlr/JavaScript.g:89:20: ( initialiserNoIn )?
                alt37 = 2
                LA37_0 = self.input.LA(1)

                if (LA37_0 == 39) :
                    alt37 = 1
                if alt37 == 1:
                    # /home/buffer/antlr/JavaScript.g:0:0: initialiserNoIn
                    pass 
                    self._state.following.append(self.FOLLOW_initialiserNoIn_in_variableDeclarationNoIn460)
                    initialiserNoIn79 = self.initialiserNoIn()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, initialiserNoIn79.tree)






                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 15, variableDeclarationNoIn_StartIndex, success)

            pass
        return retval

    # $ANTLR end "variableDeclarationNoIn"

    class initialiser_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.initialiser_return, self).__init__()

            self.tree = None




    # $ANTLR start "initialiser"
    # /home/buffer/antlr/JavaScript.g:92:1: initialiser : '=' ( LT )* assignmentExpression ;
    def initialiser(self, ):

        retval = self.initialiser_return()
        retval.start = self.input.LT(1)
        initialiser_StartIndex = self.input.index()
        root_0 = None

        char_literal80 = None
        LT81 = None
        assignmentExpression82 = None


        char_literal80_tree = None
        LT81_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 16):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:93:2: ( '=' ( LT )* assignmentExpression )
                # /home/buffer/antlr/JavaScript.g:93:4: '=' ( LT )* assignmentExpression
                pass 
                root_0 = self._adaptor.nil()

                char_literal80=self.match(self.input, 39, self.FOLLOW_39_in_initialiser473)
                if self._state.backtracking == 0:

                    char_literal80_tree = self._adaptor.createWithPayload(char_literal80)
                    self._adaptor.addChild(root_0, char_literal80_tree)

                # /home/buffer/antlr/JavaScript.g:93:10: ( LT )*
                while True: #loop38
                    alt38 = 2
                    LA38_0 = self.input.LA(1)

                    if (LA38_0 == LT) :
                        alt38 = 1


                    if alt38 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT81=self.match(self.input, LT, self.FOLLOW_LT_in_initialiser475)


                    else:
                        break #loop38
                self._state.following.append(self.FOLLOW_assignmentExpression_in_initialiser479)
                assignmentExpression82 = self.assignmentExpression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, assignmentExpression82.tree)



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 16, initialiser_StartIndex, success)

            pass
        return retval

    # $ANTLR end "initialiser"

    class initialiserNoIn_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.initialiserNoIn_return, self).__init__()

            self.tree = None




    # $ANTLR start "initialiserNoIn"
    # /home/buffer/antlr/JavaScript.g:96:1: initialiserNoIn : '=' ( LT )* assignmentExpressionNoIn ;
    def initialiserNoIn(self, ):

        retval = self.initialiserNoIn_return()
        retval.start = self.input.LT(1)
        initialiserNoIn_StartIndex = self.input.index()
        root_0 = None

        char_literal83 = None
        LT84 = None
        assignmentExpressionNoIn85 = None


        char_literal83_tree = None
        LT84_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 17):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:97:2: ( '=' ( LT )* assignmentExpressionNoIn )
                # /home/buffer/antlr/JavaScript.g:97:4: '=' ( LT )* assignmentExpressionNoIn
                pass 
                root_0 = self._adaptor.nil()

                char_literal83=self.match(self.input, 39, self.FOLLOW_39_in_initialiserNoIn491)
                if self._state.backtracking == 0:

                    char_literal83_tree = self._adaptor.createWithPayload(char_literal83)
                    self._adaptor.addChild(root_0, char_literal83_tree)

                # /home/buffer/antlr/JavaScript.g:97:10: ( LT )*
                while True: #loop39
                    alt39 = 2
                    LA39_0 = self.input.LA(1)

                    if (LA39_0 == LT) :
                        alt39 = 1


                    if alt39 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT84=self.match(self.input, LT, self.FOLLOW_LT_in_initialiserNoIn493)


                    else:
                        break #loop39
                self._state.following.append(self.FOLLOW_assignmentExpressionNoIn_in_initialiserNoIn497)
                assignmentExpressionNoIn85 = self.assignmentExpressionNoIn()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, assignmentExpressionNoIn85.tree)



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 17, initialiserNoIn_StartIndex, success)

            pass
        return retval

    # $ANTLR end "initialiserNoIn"

    class emptyStatement_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.emptyStatement_return, self).__init__()

            self.tree = None




    # $ANTLR start "emptyStatement"
    # /home/buffer/antlr/JavaScript.g:100:1: emptyStatement : ';' ;
    def emptyStatement(self, ):

        retval = self.emptyStatement_return()
        retval.start = self.input.LT(1)
        emptyStatement_StartIndex = self.input.index()
        root_0 = None

        char_literal86 = None

        char_literal86_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 18):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:101:2: ( ';' )
                # /home/buffer/antlr/JavaScript.g:101:4: ';'
                pass 
                root_0 = self._adaptor.nil()

                char_literal86=self.match(self.input, 38, self.FOLLOW_38_in_emptyStatement509)
                if self._state.backtracking == 0:

                    char_literal86_tree = self._adaptor.createWithPayload(char_literal86)
                    self._adaptor.addChild(root_0, char_literal86_tree)




                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 18, emptyStatement_StartIndex, success)

            pass
        return retval

    # $ANTLR end "emptyStatement"

    class expressionStatement_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.expressionStatement_return, self).__init__()

            self.tree = None




    # $ANTLR start "expressionStatement"
    # /home/buffer/antlr/JavaScript.g:104:1: expressionStatement : expression ( LT | ';' ) ;
    def expressionStatement(self, ):

        retval = self.expressionStatement_return()
        retval.start = self.input.LT(1)
        expressionStatement_StartIndex = self.input.index()
        root_0 = None

        set88 = None
        expression87 = None


        set88_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 19):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:105:2: ( expression ( LT | ';' ) )
                # /home/buffer/antlr/JavaScript.g:105:4: expression ( LT | ';' )
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_expression_in_expressionStatement521)
                expression87 = self.expression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, expression87.tree)
                set88 = self.input.LT(1)
                if self.input.LA(1) == LT or self.input.LA(1) == 38:
                    self.input.consume()
                    self._state.errorRecovery = False

                else:
                    if self._state.backtracking > 0:
                        raise BacktrackingFailed

                    mse = MismatchedSetException(None, self.input)
                    raise mse





                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 19, expressionStatement_StartIndex, success)

            pass
        return retval

    # $ANTLR end "expressionStatement"

    class ifStatement_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.ifStatement_return, self).__init__()

            self.tree = None




    # $ANTLR start "ifStatement"
    # /home/buffer/antlr/JavaScript.g:108:1: ifStatement : 'if' ( LT )* '(' ( LT )* expression ( LT )* ')' ( LT )* statement ( ( LT )* 'else' ( LT )* statement )? ;
    def ifStatement(self, ):

        retval = self.ifStatement_return()
        retval.start = self.input.LT(1)
        ifStatement_StartIndex = self.input.index()
        root_0 = None

        string_literal89 = None
        LT90 = None
        char_literal91 = None
        LT92 = None
        LT94 = None
        char_literal95 = None
        LT96 = None
        LT98 = None
        string_literal99 = None
        LT100 = None
        expression93 = None

        statement97 = None

        statement101 = None


        string_literal89_tree = None
        LT90_tree = None
        char_literal91_tree = None
        LT92_tree = None
        LT94_tree = None
        char_literal95_tree = None
        LT96_tree = None
        LT98_tree = None
        string_literal99_tree = None
        LT100_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 20):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:109:2: ( 'if' ( LT )* '(' ( LT )* expression ( LT )* ')' ( LT )* statement ( ( LT )* 'else' ( LT )* statement )? )
                # /home/buffer/antlr/JavaScript.g:109:4: 'if' ( LT )* '(' ( LT )* expression ( LT )* ')' ( LT )* statement ( ( LT )* 'else' ( LT )* statement )?
                pass 
                root_0 = self._adaptor.nil()

                string_literal89=self.match(self.input, 40, self.FOLLOW_40_in_ifStatement542)
                if self._state.backtracking == 0:

                    string_literal89_tree = self._adaptor.createWithPayload(string_literal89)
                    self._adaptor.addChild(root_0, string_literal89_tree)

                # /home/buffer/antlr/JavaScript.g:109:11: ( LT )*
                while True: #loop40
                    alt40 = 2
                    LA40_0 = self.input.LA(1)

                    if (LA40_0 == LT) :
                        alt40 = 1


                    if alt40 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT90=self.match(self.input, LT, self.FOLLOW_LT_in_ifStatement544)


                    else:
                        break #loop40
                char_literal91=self.match(self.input, 32, self.FOLLOW_32_in_ifStatement548)
                if self._state.backtracking == 0:

                    char_literal91_tree = self._adaptor.createWithPayload(char_literal91)
                    self._adaptor.addChild(root_0, char_literal91_tree)

                # /home/buffer/antlr/JavaScript.g:109:20: ( LT )*
                while True: #loop41
                    alt41 = 2
                    LA41_0 = self.input.LA(1)

                    if (LA41_0 == LT) :
                        alt41 = 1


                    if alt41 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT92=self.match(self.input, LT, self.FOLLOW_LT_in_ifStatement550)


                    else:
                        break #loop41
                self._state.following.append(self.FOLLOW_expression_in_ifStatement554)
                expression93 = self.expression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, expression93.tree)
                # /home/buffer/antlr/JavaScript.g:109:36: ( LT )*
                while True: #loop42
                    alt42 = 2
                    LA42_0 = self.input.LA(1)

                    if (LA42_0 == LT) :
                        alt42 = 1


                    if alt42 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT94=self.match(self.input, LT, self.FOLLOW_LT_in_ifStatement556)


                    else:
                        break #loop42
                char_literal95=self.match(self.input, 34, self.FOLLOW_34_in_ifStatement560)
                if self._state.backtracking == 0:

                    char_literal95_tree = self._adaptor.createWithPayload(char_literal95)
                    self._adaptor.addChild(root_0, char_literal95_tree)

                # /home/buffer/antlr/JavaScript.g:109:45: ( LT )*
                while True: #loop43
                    alt43 = 2
                    LA43_0 = self.input.LA(1)

                    if (LA43_0 == LT) :
                        alt43 = 1


                    if alt43 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT96=self.match(self.input, LT, self.FOLLOW_LT_in_ifStatement562)


                    else:
                        break #loop43
                self._state.following.append(self.FOLLOW_statement_in_ifStatement566)
                statement97 = self.statement()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, statement97.tree)
                # /home/buffer/antlr/JavaScript.g:109:58: ( ( LT )* 'else' ( LT )* statement )?
                alt46 = 2
                LA46_0 = self.input.LA(1)

                if (LA46_0 == LT) :
                    LA46_1 = self.input.LA(2)

                    if (self.synpred60_JavaScript()) :
                        alt46 = 1
                elif (LA46_0 == 41) :
                    LA46_2 = self.input.LA(2)

                    if (self.synpred60_JavaScript()) :
                        alt46 = 1
                if alt46 == 1:
                    # /home/buffer/antlr/JavaScript.g:109:59: ( LT )* 'else' ( LT )* statement
                    pass 
                    # /home/buffer/antlr/JavaScript.g:109:61: ( LT )*
                    while True: #loop44
                        alt44 = 2
                        LA44_0 = self.input.LA(1)

                        if (LA44_0 == LT) :
                            alt44 = 1


                        if alt44 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT98=self.match(self.input, LT, self.FOLLOW_LT_in_ifStatement569)


                        else:
                            break #loop44
                    string_literal99=self.match(self.input, 41, self.FOLLOW_41_in_ifStatement573)
                    if self._state.backtracking == 0:

                        string_literal99_tree = self._adaptor.createWithPayload(string_literal99)
                        self._adaptor.addChild(root_0, string_literal99_tree)

                    # /home/buffer/antlr/JavaScript.g:109:73: ( LT )*
                    while True: #loop45
                        alt45 = 2
                        LA45_0 = self.input.LA(1)

                        if (LA45_0 == LT) :
                            alt45 = 1


                        if alt45 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT100=self.match(self.input, LT, self.FOLLOW_LT_in_ifStatement575)


                        else:
                            break #loop45
                    self._state.following.append(self.FOLLOW_statement_in_ifStatement579)
                    statement101 = self.statement()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, statement101.tree)






                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 20, ifStatement_StartIndex, success)

            pass
        return retval

    # $ANTLR end "ifStatement"

    class iterationStatement_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.iterationStatement_return, self).__init__()

            self.tree = None




    # $ANTLR start "iterationStatement"
    # /home/buffer/antlr/JavaScript.g:112:1: iterationStatement : ( doWhileStatement | whileStatement | forStatement | forInStatement );
    def iterationStatement(self, ):

        retval = self.iterationStatement_return()
        retval.start = self.input.LT(1)
        iterationStatement_StartIndex = self.input.index()
        root_0 = None

        doWhileStatement102 = None

        whileStatement103 = None

        forStatement104 = None

        forInStatement105 = None



        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 21):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:113:2: ( doWhileStatement | whileStatement | forStatement | forInStatement )
                alt47 = 4
                LA47 = self.input.LA(1)
                if LA47 == 42:
                    alt47 = 1
                elif LA47 == 43:
                    alt47 = 2
                elif LA47 == 44:
                    LA47_3 = self.input.LA(2)

                    if (self.synpred63_JavaScript()) :
                        alt47 = 3
                    elif (True) :
                        alt47 = 4
                    else:
                        if self._state.backtracking > 0:
                            raise BacktrackingFailed

                        nvae = NoViableAltException("", 47, 3, self.input)

                        raise nvae

                else:
                    if self._state.backtracking > 0:
                        raise BacktrackingFailed

                    nvae = NoViableAltException("", 47, 0, self.input)

                    raise nvae

                if alt47 == 1:
                    # /home/buffer/antlr/JavaScript.g:113:4: doWhileStatement
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_doWhileStatement_in_iterationStatement593)
                    doWhileStatement102 = self.doWhileStatement()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, doWhileStatement102.tree)


                elif alt47 == 2:
                    # /home/buffer/antlr/JavaScript.g:114:4: whileStatement
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_whileStatement_in_iterationStatement598)
                    whileStatement103 = self.whileStatement()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, whileStatement103.tree)


                elif alt47 == 3:
                    # /home/buffer/antlr/JavaScript.g:115:4: forStatement
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_forStatement_in_iterationStatement603)
                    forStatement104 = self.forStatement()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, forStatement104.tree)


                elif alt47 == 4:
                    # /home/buffer/antlr/JavaScript.g:116:4: forInStatement
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_forInStatement_in_iterationStatement608)
                    forInStatement105 = self.forInStatement()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, forInStatement105.tree)


                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 21, iterationStatement_StartIndex, success)

            pass
        return retval

    # $ANTLR end "iterationStatement"

    class doWhileStatement_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.doWhileStatement_return, self).__init__()

            self.tree = None




    # $ANTLR start "doWhileStatement"
    # /home/buffer/antlr/JavaScript.g:119:1: doWhileStatement : 'do' ( LT )* statement ( LT )* 'while' ( LT )* '(' expression ')' ( LT | ';' ) ;
    def doWhileStatement(self, ):

        retval = self.doWhileStatement_return()
        retval.start = self.input.LT(1)
        doWhileStatement_StartIndex = self.input.index()
        root_0 = None

        string_literal106 = None
        LT107 = None
        LT109 = None
        string_literal110 = None
        LT111 = None
        char_literal112 = None
        char_literal114 = None
        set115 = None
        statement108 = None

        expression113 = None


        string_literal106_tree = None
        LT107_tree = None
        LT109_tree = None
        string_literal110_tree = None
        LT111_tree = None
        char_literal112_tree = None
        char_literal114_tree = None
        set115_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 22):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:120:2: ( 'do' ( LT )* statement ( LT )* 'while' ( LT )* '(' expression ')' ( LT | ';' ) )
                # /home/buffer/antlr/JavaScript.g:120:4: 'do' ( LT )* statement ( LT )* 'while' ( LT )* '(' expression ')' ( LT | ';' )
                pass 
                root_0 = self._adaptor.nil()

                string_literal106=self.match(self.input, 42, self.FOLLOW_42_in_doWhileStatement620)
                if self._state.backtracking == 0:

                    string_literal106_tree = self._adaptor.createWithPayload(string_literal106)
                    self._adaptor.addChild(root_0, string_literal106_tree)

                # /home/buffer/antlr/JavaScript.g:120:11: ( LT )*
                while True: #loop48
                    alt48 = 2
                    LA48_0 = self.input.LA(1)

                    if (LA48_0 == LT) :
                        alt48 = 1


                    if alt48 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT107=self.match(self.input, LT, self.FOLLOW_LT_in_doWhileStatement622)


                    else:
                        break #loop48
                self._state.following.append(self.FOLLOW_statement_in_doWhileStatement626)
                statement108 = self.statement()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, statement108.tree)
                # /home/buffer/antlr/JavaScript.g:120:26: ( LT )*
                while True: #loop49
                    alt49 = 2
                    LA49_0 = self.input.LA(1)

                    if (LA49_0 == LT) :
                        alt49 = 1


                    if alt49 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT109=self.match(self.input, LT, self.FOLLOW_LT_in_doWhileStatement628)


                    else:
                        break #loop49
                string_literal110=self.match(self.input, 43, self.FOLLOW_43_in_doWhileStatement632)
                if self._state.backtracking == 0:

                    string_literal110_tree = self._adaptor.createWithPayload(string_literal110)
                    self._adaptor.addChild(root_0, string_literal110_tree)

                # /home/buffer/antlr/JavaScript.g:120:39: ( LT )*
                while True: #loop50
                    alt50 = 2
                    LA50_0 = self.input.LA(1)

                    if (LA50_0 == LT) :
                        alt50 = 1


                    if alt50 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT111=self.match(self.input, LT, self.FOLLOW_LT_in_doWhileStatement634)


                    else:
                        break #loop50
                char_literal112=self.match(self.input, 32, self.FOLLOW_32_in_doWhileStatement638)
                if self._state.backtracking == 0:

                    char_literal112_tree = self._adaptor.createWithPayload(char_literal112)
                    self._adaptor.addChild(root_0, char_literal112_tree)

                self._state.following.append(self.FOLLOW_expression_in_doWhileStatement640)
                expression113 = self.expression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, expression113.tree)
                char_literal114=self.match(self.input, 34, self.FOLLOW_34_in_doWhileStatement642)
                if self._state.backtracking == 0:

                    char_literal114_tree = self._adaptor.createWithPayload(char_literal114)
                    self._adaptor.addChild(root_0, char_literal114_tree)

                set115 = self.input.LT(1)
                if self.input.LA(1) == LT or self.input.LA(1) == 38:
                    self.input.consume()
                    self._state.errorRecovery = False

                else:
                    if self._state.backtracking > 0:
                        raise BacktrackingFailed

                    mse = MismatchedSetException(None, self.input)
                    raise mse





                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 22, doWhileStatement_StartIndex, success)

            pass
        return retval

    # $ANTLR end "doWhileStatement"

    class whileStatement_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.whileStatement_return, self).__init__()

            self.tree = None




    # $ANTLR start "whileStatement"
    # /home/buffer/antlr/JavaScript.g:123:1: whileStatement : 'while' ( LT )* '(' ( LT )* expression ( LT )* ')' ( LT )* statement ;
    def whileStatement(self, ):

        retval = self.whileStatement_return()
        retval.start = self.input.LT(1)
        whileStatement_StartIndex = self.input.index()
        root_0 = None

        string_literal116 = None
        LT117 = None
        char_literal118 = None
        LT119 = None
        LT121 = None
        char_literal122 = None
        LT123 = None
        expression120 = None

        statement124 = None


        string_literal116_tree = None
        LT117_tree = None
        char_literal118_tree = None
        LT119_tree = None
        LT121_tree = None
        char_literal122_tree = None
        LT123_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 23):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:124:2: ( 'while' ( LT )* '(' ( LT )* expression ( LT )* ')' ( LT )* statement )
                # /home/buffer/antlr/JavaScript.g:124:4: 'while' ( LT )* '(' ( LT )* expression ( LT )* ')' ( LT )* statement
                pass 
                root_0 = self._adaptor.nil()

                string_literal116=self.match(self.input, 43, self.FOLLOW_43_in_whileStatement663)
                if self._state.backtracking == 0:

                    string_literal116_tree = self._adaptor.createWithPayload(string_literal116)
                    self._adaptor.addChild(root_0, string_literal116_tree)

                # /home/buffer/antlr/JavaScript.g:124:14: ( LT )*
                while True: #loop51
                    alt51 = 2
                    LA51_0 = self.input.LA(1)

                    if (LA51_0 == LT) :
                        alt51 = 1


                    if alt51 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT117=self.match(self.input, LT, self.FOLLOW_LT_in_whileStatement665)


                    else:
                        break #loop51
                char_literal118=self.match(self.input, 32, self.FOLLOW_32_in_whileStatement669)
                if self._state.backtracking == 0:

                    char_literal118_tree = self._adaptor.createWithPayload(char_literal118)
                    self._adaptor.addChild(root_0, char_literal118_tree)

                # /home/buffer/antlr/JavaScript.g:124:23: ( LT )*
                while True: #loop52
                    alt52 = 2
                    LA52_0 = self.input.LA(1)

                    if (LA52_0 == LT) :
                        alt52 = 1


                    if alt52 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT119=self.match(self.input, LT, self.FOLLOW_LT_in_whileStatement671)


                    else:
                        break #loop52
                self._state.following.append(self.FOLLOW_expression_in_whileStatement675)
                expression120 = self.expression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, expression120.tree)
                # /home/buffer/antlr/JavaScript.g:124:39: ( LT )*
                while True: #loop53
                    alt53 = 2
                    LA53_0 = self.input.LA(1)

                    if (LA53_0 == LT) :
                        alt53 = 1


                    if alt53 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT121=self.match(self.input, LT, self.FOLLOW_LT_in_whileStatement677)


                    else:
                        break #loop53
                char_literal122=self.match(self.input, 34, self.FOLLOW_34_in_whileStatement681)
                if self._state.backtracking == 0:

                    char_literal122_tree = self._adaptor.createWithPayload(char_literal122)
                    self._adaptor.addChild(root_0, char_literal122_tree)

                # /home/buffer/antlr/JavaScript.g:124:48: ( LT )*
                while True: #loop54
                    alt54 = 2
                    LA54_0 = self.input.LA(1)

                    if (LA54_0 == LT) :
                        alt54 = 1


                    if alt54 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT123=self.match(self.input, LT, self.FOLLOW_LT_in_whileStatement683)


                    else:
                        break #loop54
                self._state.following.append(self.FOLLOW_statement_in_whileStatement687)
                statement124 = self.statement()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, statement124.tree)



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 23, whileStatement_StartIndex, success)

            pass
        return retval

    # $ANTLR end "whileStatement"

    class forStatement_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.forStatement_return, self).__init__()

            self.tree = None




    # $ANTLR start "forStatement"
    # /home/buffer/antlr/JavaScript.g:127:1: forStatement : 'for' ( LT )* '(' ( ( LT )* forStatementInitialiserPart )? ( LT )* ';' ( ( LT )* expression )? ( LT )* ';' ( ( LT )* expression )? ( LT )* ')' ( LT )* statement ;
    def forStatement(self, ):

        retval = self.forStatement_return()
        retval.start = self.input.LT(1)
        forStatement_StartIndex = self.input.index()
        root_0 = None

        string_literal125 = None
        LT126 = None
        char_literal127 = None
        LT128 = None
        LT130 = None
        char_literal131 = None
        LT132 = None
        LT134 = None
        char_literal135 = None
        LT136 = None
        LT138 = None
        char_literal139 = None
        LT140 = None
        forStatementInitialiserPart129 = None

        expression133 = None

        expression137 = None

        statement141 = None


        string_literal125_tree = None
        LT126_tree = None
        char_literal127_tree = None
        LT128_tree = None
        LT130_tree = None
        char_literal131_tree = None
        LT132_tree = None
        LT134_tree = None
        char_literal135_tree = None
        LT136_tree = None
        LT138_tree = None
        char_literal139_tree = None
        LT140_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 24):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:128:2: ( 'for' ( LT )* '(' ( ( LT )* forStatementInitialiserPart )? ( LT )* ';' ( ( LT )* expression )? ( LT )* ';' ( ( LT )* expression )? ( LT )* ')' ( LT )* statement )
                # /home/buffer/antlr/JavaScript.g:128:4: 'for' ( LT )* '(' ( ( LT )* forStatementInitialiserPart )? ( LT )* ';' ( ( LT )* expression )? ( LT )* ';' ( ( LT )* expression )? ( LT )* ')' ( LT )* statement
                pass 
                root_0 = self._adaptor.nil()

                string_literal125=self.match(self.input, 44, self.FOLLOW_44_in_forStatement699)
                if self._state.backtracking == 0:

                    string_literal125_tree = self._adaptor.createWithPayload(string_literal125)
                    self._adaptor.addChild(root_0, string_literal125_tree)

                # /home/buffer/antlr/JavaScript.g:128:12: ( LT )*
                while True: #loop55
                    alt55 = 2
                    LA55_0 = self.input.LA(1)

                    if (LA55_0 == LT) :
                        alt55 = 1


                    if alt55 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT126=self.match(self.input, LT, self.FOLLOW_LT_in_forStatement701)


                    else:
                        break #loop55
                char_literal127=self.match(self.input, 32, self.FOLLOW_32_in_forStatement705)
                if self._state.backtracking == 0:

                    char_literal127_tree = self._adaptor.createWithPayload(char_literal127)
                    self._adaptor.addChild(root_0, char_literal127_tree)

                # /home/buffer/antlr/JavaScript.g:128:19: ( ( LT )* forStatementInitialiserPart )?
                alt57 = 2
                alt57 = self.dfa57.predict(self.input)
                if alt57 == 1:
                    # /home/buffer/antlr/JavaScript.g:128:20: ( LT )* forStatementInitialiserPart
                    pass 
                    # /home/buffer/antlr/JavaScript.g:128:22: ( LT )*
                    while True: #loop56
                        alt56 = 2
                        LA56_0 = self.input.LA(1)

                        if (LA56_0 == LT) :
                            alt56 = 1


                        if alt56 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT128=self.match(self.input, LT, self.FOLLOW_LT_in_forStatement708)


                        else:
                            break #loop56
                    self._state.following.append(self.FOLLOW_forStatementInitialiserPart_in_forStatement712)
                    forStatementInitialiserPart129 = self.forStatementInitialiserPart()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, forStatementInitialiserPart129.tree)



                # /home/buffer/antlr/JavaScript.g:128:57: ( LT )*
                while True: #loop58
                    alt58 = 2
                    LA58_0 = self.input.LA(1)

                    if (LA58_0 == LT) :
                        alt58 = 1


                    if alt58 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT130=self.match(self.input, LT, self.FOLLOW_LT_in_forStatement716)


                    else:
                        break #loop58
                char_literal131=self.match(self.input, 38, self.FOLLOW_38_in_forStatement720)
                if self._state.backtracking == 0:

                    char_literal131_tree = self._adaptor.createWithPayload(char_literal131)
                    self._adaptor.addChild(root_0, char_literal131_tree)

                # /home/buffer/antlr/JavaScript.g:128:64: ( ( LT )* expression )?
                alt60 = 2
                alt60 = self.dfa60.predict(self.input)
                if alt60 == 1:
                    # /home/buffer/antlr/JavaScript.g:128:65: ( LT )* expression
                    pass 
                    # /home/buffer/antlr/JavaScript.g:128:67: ( LT )*
                    while True: #loop59
                        alt59 = 2
                        LA59_0 = self.input.LA(1)

                        if (LA59_0 == LT) :
                            alt59 = 1


                        if alt59 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT132=self.match(self.input, LT, self.FOLLOW_LT_in_forStatement723)


                        else:
                            break #loop59
                    self._state.following.append(self.FOLLOW_expression_in_forStatement727)
                    expression133 = self.expression()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, expression133.tree)



                # /home/buffer/antlr/JavaScript.g:128:85: ( LT )*
                while True: #loop61
                    alt61 = 2
                    LA61_0 = self.input.LA(1)

                    if (LA61_0 == LT) :
                        alt61 = 1


                    if alt61 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT134=self.match(self.input, LT, self.FOLLOW_LT_in_forStatement731)


                    else:
                        break #loop61
                char_literal135=self.match(self.input, 38, self.FOLLOW_38_in_forStatement735)
                if self._state.backtracking == 0:

                    char_literal135_tree = self._adaptor.createWithPayload(char_literal135)
                    self._adaptor.addChild(root_0, char_literal135_tree)

                # /home/buffer/antlr/JavaScript.g:128:92: ( ( LT )* expression )?
                alt63 = 2
                alt63 = self.dfa63.predict(self.input)
                if alt63 == 1:
                    # /home/buffer/antlr/JavaScript.g:128:93: ( LT )* expression
                    pass 
                    # /home/buffer/antlr/JavaScript.g:128:95: ( LT )*
                    while True: #loop62
                        alt62 = 2
                        LA62_0 = self.input.LA(1)

                        if (LA62_0 == LT) :
                            alt62 = 1


                        if alt62 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT136=self.match(self.input, LT, self.FOLLOW_LT_in_forStatement738)


                        else:
                            break #loop62
                    self._state.following.append(self.FOLLOW_expression_in_forStatement742)
                    expression137 = self.expression()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, expression137.tree)



                # /home/buffer/antlr/JavaScript.g:128:113: ( LT )*
                while True: #loop64
                    alt64 = 2
                    LA64_0 = self.input.LA(1)

                    if (LA64_0 == LT) :
                        alt64 = 1


                    if alt64 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT138=self.match(self.input, LT, self.FOLLOW_LT_in_forStatement746)


                    else:
                        break #loop64
                char_literal139=self.match(self.input, 34, self.FOLLOW_34_in_forStatement750)
                if self._state.backtracking == 0:

                    char_literal139_tree = self._adaptor.createWithPayload(char_literal139)
                    self._adaptor.addChild(root_0, char_literal139_tree)

                # /home/buffer/antlr/JavaScript.g:128:122: ( LT )*
                while True: #loop65
                    alt65 = 2
                    LA65_0 = self.input.LA(1)

                    if (LA65_0 == LT) :
                        alt65 = 1


                    if alt65 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT140=self.match(self.input, LT, self.FOLLOW_LT_in_forStatement752)


                    else:
                        break #loop65
                self._state.following.append(self.FOLLOW_statement_in_forStatement756)
                statement141 = self.statement()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, statement141.tree)



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 24, forStatement_StartIndex, success)

            pass
        return retval

    # $ANTLR end "forStatement"

    class forStatementInitialiserPart_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.forStatementInitialiserPart_return, self).__init__()

            self.tree = None




    # $ANTLR start "forStatementInitialiserPart"
    # /home/buffer/antlr/JavaScript.g:131:1: forStatementInitialiserPart : ( expressionNoIn | 'var' ( LT )* variableDeclarationListNoIn );
    def forStatementInitialiserPart(self, ):

        retval = self.forStatementInitialiserPart_return()
        retval.start = self.input.LT(1)
        forStatementInitialiserPart_StartIndex = self.input.index()
        root_0 = None

        string_literal143 = None
        LT144 = None
        expressionNoIn142 = None

        variableDeclarationListNoIn145 = None


        string_literal143_tree = None
        LT144_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 25):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:132:2: ( expressionNoIn | 'var' ( LT )* variableDeclarationListNoIn )
                alt67 = 2
                LA67_0 = self.input.LA(1)

                if ((Identifier <= LA67_0 <= NumericLiteral) or (31 <= LA67_0 <= 32) or LA67_0 == 35 or (58 <= LA67_0 <= 59) or (91 <= LA67_0 <= 92) or (96 <= LA67_0 <= 106)) :
                    alt67 = 1
                elif (LA67_0 == 37) :
                    alt67 = 2
                else:
                    if self._state.backtracking > 0:
                        raise BacktrackingFailed

                    nvae = NoViableAltException("", 67, 0, self.input)

                    raise nvae

                if alt67 == 1:
                    # /home/buffer/antlr/JavaScript.g:132:4: expressionNoIn
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_expressionNoIn_in_forStatementInitialiserPart768)
                    expressionNoIn142 = self.expressionNoIn()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, expressionNoIn142.tree)


                elif alt67 == 2:
                    # /home/buffer/antlr/JavaScript.g:133:4: 'var' ( LT )* variableDeclarationListNoIn
                    pass 
                    root_0 = self._adaptor.nil()

                    string_literal143=self.match(self.input, 37, self.FOLLOW_37_in_forStatementInitialiserPart773)
                    if self._state.backtracking == 0:

                        string_literal143_tree = self._adaptor.createWithPayload(string_literal143)
                        self._adaptor.addChild(root_0, string_literal143_tree)

                    # /home/buffer/antlr/JavaScript.g:133:12: ( LT )*
                    while True: #loop66
                        alt66 = 2
                        LA66_0 = self.input.LA(1)

                        if (LA66_0 == LT) :
                            alt66 = 1


                        if alt66 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT144=self.match(self.input, LT, self.FOLLOW_LT_in_forStatementInitialiserPart775)


                        else:
                            break #loop66
                    self._state.following.append(self.FOLLOW_variableDeclarationListNoIn_in_forStatementInitialiserPart779)
                    variableDeclarationListNoIn145 = self.variableDeclarationListNoIn()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, variableDeclarationListNoIn145.tree)


                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 25, forStatementInitialiserPart_StartIndex, success)

            pass
        return retval

    # $ANTLR end "forStatementInitialiserPart"

    class forInStatement_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.forInStatement_return, self).__init__()

            self.tree = None




    # $ANTLR start "forInStatement"
    # /home/buffer/antlr/JavaScript.g:136:1: forInStatement : 'for' ( LT )* '(' ( LT )* forInStatementInitialiserPart ( LT )* 'in' ( LT )* expression ( LT )* ')' ( LT )* statement ;
    def forInStatement(self, ):

        retval = self.forInStatement_return()
        retval.start = self.input.LT(1)
        forInStatement_StartIndex = self.input.index()
        root_0 = None

        string_literal146 = None
        LT147 = None
        char_literal148 = None
        LT149 = None
        LT151 = None
        string_literal152 = None
        LT153 = None
        LT155 = None
        char_literal156 = None
        LT157 = None
        forInStatementInitialiserPart150 = None

        expression154 = None

        statement158 = None


        string_literal146_tree = None
        LT147_tree = None
        char_literal148_tree = None
        LT149_tree = None
        LT151_tree = None
        string_literal152_tree = None
        LT153_tree = None
        LT155_tree = None
        char_literal156_tree = None
        LT157_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 26):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:137:2: ( 'for' ( LT )* '(' ( LT )* forInStatementInitialiserPart ( LT )* 'in' ( LT )* expression ( LT )* ')' ( LT )* statement )
                # /home/buffer/antlr/JavaScript.g:137:4: 'for' ( LT )* '(' ( LT )* forInStatementInitialiserPart ( LT )* 'in' ( LT )* expression ( LT )* ')' ( LT )* statement
                pass 
                root_0 = self._adaptor.nil()

                string_literal146=self.match(self.input, 44, self.FOLLOW_44_in_forInStatement791)
                if self._state.backtracking == 0:

                    string_literal146_tree = self._adaptor.createWithPayload(string_literal146)
                    self._adaptor.addChild(root_0, string_literal146_tree)

                # /home/buffer/antlr/JavaScript.g:137:12: ( LT )*
                while True: #loop68
                    alt68 = 2
                    LA68_0 = self.input.LA(1)

                    if (LA68_0 == LT) :
                        alt68 = 1


                    if alt68 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT147=self.match(self.input, LT, self.FOLLOW_LT_in_forInStatement793)


                    else:
                        break #loop68
                char_literal148=self.match(self.input, 32, self.FOLLOW_32_in_forInStatement797)
                if self._state.backtracking == 0:

                    char_literal148_tree = self._adaptor.createWithPayload(char_literal148)
                    self._adaptor.addChild(root_0, char_literal148_tree)

                # /home/buffer/antlr/JavaScript.g:137:21: ( LT )*
                while True: #loop69
                    alt69 = 2
                    LA69_0 = self.input.LA(1)

                    if (LA69_0 == LT) :
                        alt69 = 1


                    if alt69 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT149=self.match(self.input, LT, self.FOLLOW_LT_in_forInStatement799)


                    else:
                        break #loop69
                self._state.following.append(self.FOLLOW_forInStatementInitialiserPart_in_forInStatement803)
                forInStatementInitialiserPart150 = self.forInStatementInitialiserPart()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, forInStatementInitialiserPart150.tree)
                # /home/buffer/antlr/JavaScript.g:137:56: ( LT )*
                while True: #loop70
                    alt70 = 2
                    LA70_0 = self.input.LA(1)

                    if (LA70_0 == LT) :
                        alt70 = 1


                    if alt70 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT151=self.match(self.input, LT, self.FOLLOW_LT_in_forInStatement805)


                    else:
                        break #loop70
                string_literal152=self.match(self.input, 45, self.FOLLOW_45_in_forInStatement809)
                if self._state.backtracking == 0:

                    string_literal152_tree = self._adaptor.createWithPayload(string_literal152)
                    self._adaptor.addChild(root_0, string_literal152_tree)

                # /home/buffer/antlr/JavaScript.g:137:66: ( LT )*
                while True: #loop71
                    alt71 = 2
                    LA71_0 = self.input.LA(1)

                    if (LA71_0 == LT) :
                        alt71 = 1


                    if alt71 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT153=self.match(self.input, LT, self.FOLLOW_LT_in_forInStatement811)


                    else:
                        break #loop71
                self._state.following.append(self.FOLLOW_expression_in_forInStatement815)
                expression154 = self.expression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, expression154.tree)
                # /home/buffer/antlr/JavaScript.g:137:82: ( LT )*
                while True: #loop72
                    alt72 = 2
                    LA72_0 = self.input.LA(1)

                    if (LA72_0 == LT) :
                        alt72 = 1


                    if alt72 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT155=self.match(self.input, LT, self.FOLLOW_LT_in_forInStatement817)


                    else:
                        break #loop72
                char_literal156=self.match(self.input, 34, self.FOLLOW_34_in_forInStatement821)
                if self._state.backtracking == 0:

                    char_literal156_tree = self._adaptor.createWithPayload(char_literal156)
                    self._adaptor.addChild(root_0, char_literal156_tree)

                # /home/buffer/antlr/JavaScript.g:137:91: ( LT )*
                while True: #loop73
                    alt73 = 2
                    LA73_0 = self.input.LA(1)

                    if (LA73_0 == LT) :
                        alt73 = 1


                    if alt73 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT157=self.match(self.input, LT, self.FOLLOW_LT_in_forInStatement823)


                    else:
                        break #loop73
                self._state.following.append(self.FOLLOW_statement_in_forInStatement827)
                statement158 = self.statement()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, statement158.tree)



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 26, forInStatement_StartIndex, success)

            pass
        return retval

    # $ANTLR end "forInStatement"

    class forInStatementInitialiserPart_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.forInStatementInitialiserPart_return, self).__init__()

            self.tree = None




    # $ANTLR start "forInStatementInitialiserPart"
    # /home/buffer/antlr/JavaScript.g:140:1: forInStatementInitialiserPart : ( leftHandSideExpression | 'var' ( LT )* variableDeclarationNoIn );
    def forInStatementInitialiserPart(self, ):

        retval = self.forInStatementInitialiserPart_return()
        retval.start = self.input.LT(1)
        forInStatementInitialiserPart_StartIndex = self.input.index()
        root_0 = None

        string_literal160 = None
        LT161 = None
        leftHandSideExpression159 = None

        variableDeclarationNoIn162 = None


        string_literal160_tree = None
        LT161_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 27):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:141:2: ( leftHandSideExpression | 'var' ( LT )* variableDeclarationNoIn )
                alt75 = 2
                LA75_0 = self.input.LA(1)

                if ((Identifier <= LA75_0 <= NumericLiteral) or (31 <= LA75_0 <= 32) or LA75_0 == 35 or (58 <= LA75_0 <= 59) or (103 <= LA75_0 <= 106)) :
                    alt75 = 1
                elif (LA75_0 == 37) :
                    alt75 = 2
                else:
                    if self._state.backtracking > 0:
                        raise BacktrackingFailed

                    nvae = NoViableAltException("", 75, 0, self.input)

                    raise nvae

                if alt75 == 1:
                    # /home/buffer/antlr/JavaScript.g:141:4: leftHandSideExpression
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_leftHandSideExpression_in_forInStatementInitialiserPart839)
                    leftHandSideExpression159 = self.leftHandSideExpression()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, leftHandSideExpression159.tree)


                elif alt75 == 2:
                    # /home/buffer/antlr/JavaScript.g:142:4: 'var' ( LT )* variableDeclarationNoIn
                    pass 
                    root_0 = self._adaptor.nil()

                    string_literal160=self.match(self.input, 37, self.FOLLOW_37_in_forInStatementInitialiserPart844)
                    if self._state.backtracking == 0:

                        string_literal160_tree = self._adaptor.createWithPayload(string_literal160)
                        self._adaptor.addChild(root_0, string_literal160_tree)

                    # /home/buffer/antlr/JavaScript.g:142:12: ( LT )*
                    while True: #loop74
                        alt74 = 2
                        LA74_0 = self.input.LA(1)

                        if (LA74_0 == LT) :
                            alt74 = 1


                        if alt74 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT161=self.match(self.input, LT, self.FOLLOW_LT_in_forInStatementInitialiserPart846)


                        else:
                            break #loop74
                    self._state.following.append(self.FOLLOW_variableDeclarationNoIn_in_forInStatementInitialiserPart850)
                    variableDeclarationNoIn162 = self.variableDeclarationNoIn()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, variableDeclarationNoIn162.tree)


                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 27, forInStatementInitialiserPart_StartIndex, success)

            pass
        return retval

    # $ANTLR end "forInStatementInitialiserPart"

    class continueStatement_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.continueStatement_return, self).__init__()

            self.tree = None




    # $ANTLR start "continueStatement"
    # /home/buffer/antlr/JavaScript.g:145:1: continueStatement : 'continue' ( Identifier )? ( LT | ';' ) ;
    def continueStatement(self, ):

        retval = self.continueStatement_return()
        retval.start = self.input.LT(1)
        continueStatement_StartIndex = self.input.index()
        root_0 = None

        string_literal163 = None
        Identifier164 = None
        set165 = None

        string_literal163_tree = None
        Identifier164_tree = None
        set165_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 28):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:146:2: ( 'continue' ( Identifier )? ( LT | ';' ) )
                # /home/buffer/antlr/JavaScript.g:146:4: 'continue' ( Identifier )? ( LT | ';' )
                pass 
                root_0 = self._adaptor.nil()

                string_literal163=self.match(self.input, 46, self.FOLLOW_46_in_continueStatement861)
                if self._state.backtracking == 0:

                    string_literal163_tree = self._adaptor.createWithPayload(string_literal163)
                    self._adaptor.addChild(root_0, string_literal163_tree)

                # /home/buffer/antlr/JavaScript.g:146:15: ( Identifier )?
                alt76 = 2
                LA76_0 = self.input.LA(1)

                if (LA76_0 == Identifier) :
                    alt76 = 1
                if alt76 == 1:
                    # /home/buffer/antlr/JavaScript.g:0:0: Identifier
                    pass 
                    Identifier164=self.match(self.input, Identifier, self.FOLLOW_Identifier_in_continueStatement863)
                    if self._state.backtracking == 0:

                        Identifier164_tree = self._adaptor.createWithPayload(Identifier164)
                        self._adaptor.addChild(root_0, Identifier164_tree)




                set165 = self.input.LT(1)
                if self.input.LA(1) == LT or self.input.LA(1) == 38:
                    self.input.consume()
                    self._state.errorRecovery = False

                else:
                    if self._state.backtracking > 0:
                        raise BacktrackingFailed

                    mse = MismatchedSetException(None, self.input)
                    raise mse





                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 28, continueStatement_StartIndex, success)

            pass
        return retval

    # $ANTLR end "continueStatement"

    class breakStatement_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.breakStatement_return, self).__init__()

            self.tree = None




    # $ANTLR start "breakStatement"
    # /home/buffer/antlr/JavaScript.g:149:1: breakStatement : 'break' ( Identifier )? ( LT | ';' ) ;
    def breakStatement(self, ):

        retval = self.breakStatement_return()
        retval.start = self.input.LT(1)
        breakStatement_StartIndex = self.input.index()
        root_0 = None

        string_literal166 = None
        Identifier167 = None
        set168 = None

        string_literal166_tree = None
        Identifier167_tree = None
        set168_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 29):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:150:2: ( 'break' ( Identifier )? ( LT | ';' ) )
                # /home/buffer/antlr/JavaScript.g:150:4: 'break' ( Identifier )? ( LT | ';' )
                pass 
                root_0 = self._adaptor.nil()

                string_literal166=self.match(self.input, 47, self.FOLLOW_47_in_breakStatement884)
                if self._state.backtracking == 0:

                    string_literal166_tree = self._adaptor.createWithPayload(string_literal166)
                    self._adaptor.addChild(root_0, string_literal166_tree)

                # /home/buffer/antlr/JavaScript.g:150:12: ( Identifier )?
                alt77 = 2
                LA77_0 = self.input.LA(1)

                if (LA77_0 == Identifier) :
                    alt77 = 1
                if alt77 == 1:
                    # /home/buffer/antlr/JavaScript.g:0:0: Identifier
                    pass 
                    Identifier167=self.match(self.input, Identifier, self.FOLLOW_Identifier_in_breakStatement886)
                    if self._state.backtracking == 0:

                        Identifier167_tree = self._adaptor.createWithPayload(Identifier167)
                        self._adaptor.addChild(root_0, Identifier167_tree)




                set168 = self.input.LT(1)
                if self.input.LA(1) == LT or self.input.LA(1) == 38:
                    self.input.consume()
                    self._state.errorRecovery = False

                else:
                    if self._state.backtracking > 0:
                        raise BacktrackingFailed

                    mse = MismatchedSetException(None, self.input)
                    raise mse





                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 29, breakStatement_StartIndex, success)

            pass
        return retval

    # $ANTLR end "breakStatement"

    class returnStatement_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.returnStatement_return, self).__init__()

            self.tree = None




    # $ANTLR start "returnStatement"
    # /home/buffer/antlr/JavaScript.g:153:1: returnStatement : 'return' ( expression )? ( LT | ';' ) ;
    def returnStatement(self, ):

        retval = self.returnStatement_return()
        retval.start = self.input.LT(1)
        returnStatement_StartIndex = self.input.index()
        root_0 = None

        string_literal169 = None
        set171 = None
        expression170 = None


        string_literal169_tree = None
        set171_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 30):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:154:2: ( 'return' ( expression )? ( LT | ';' ) )
                # /home/buffer/antlr/JavaScript.g:154:4: 'return' ( expression )? ( LT | ';' )
                pass 
                root_0 = self._adaptor.nil()

                string_literal169=self.match(self.input, 48, self.FOLLOW_48_in_returnStatement907)
                if self._state.backtracking == 0:

                    string_literal169_tree = self._adaptor.createWithPayload(string_literal169)
                    self._adaptor.addChild(root_0, string_literal169_tree)

                # /home/buffer/antlr/JavaScript.g:154:13: ( expression )?
                alt78 = 2
                LA78_0 = self.input.LA(1)

                if ((Identifier <= LA78_0 <= NumericLiteral) or (31 <= LA78_0 <= 32) or LA78_0 == 35 or (58 <= LA78_0 <= 59) or (91 <= LA78_0 <= 92) or (96 <= LA78_0 <= 106)) :
                    alt78 = 1
                if alt78 == 1:
                    # /home/buffer/antlr/JavaScript.g:0:0: expression
                    pass 
                    self._state.following.append(self.FOLLOW_expression_in_returnStatement909)
                    expression170 = self.expression()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, expression170.tree)



                set171 = self.input.LT(1)
                if self.input.LA(1) == LT or self.input.LA(1) == 38:
                    self.input.consume()
                    self._state.errorRecovery = False

                else:
                    if self._state.backtracking > 0:
                        raise BacktrackingFailed

                    mse = MismatchedSetException(None, self.input)
                    raise mse





                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 30, returnStatement_StartIndex, success)

            pass
        return retval

    # $ANTLR end "returnStatement"

    class withStatement_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.withStatement_return, self).__init__()

            self.tree = None




    # $ANTLR start "withStatement"
    # /home/buffer/antlr/JavaScript.g:157:1: withStatement : 'with' ( LT )* '(' ( LT )* expression ( LT )* ')' ( LT )* statement ;
    def withStatement(self, ):

        retval = self.withStatement_return()
        retval.start = self.input.LT(1)
        withStatement_StartIndex = self.input.index()
        root_0 = None

        string_literal172 = None
        LT173 = None
        char_literal174 = None
        LT175 = None
        LT177 = None
        char_literal178 = None
        LT179 = None
        expression176 = None

        statement180 = None


        string_literal172_tree = None
        LT173_tree = None
        char_literal174_tree = None
        LT175_tree = None
        LT177_tree = None
        char_literal178_tree = None
        LT179_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 31):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:158:2: ( 'with' ( LT )* '(' ( LT )* expression ( LT )* ')' ( LT )* statement )
                # /home/buffer/antlr/JavaScript.g:158:4: 'with' ( LT )* '(' ( LT )* expression ( LT )* ')' ( LT )* statement
                pass 
                root_0 = self._adaptor.nil()

                string_literal172=self.match(self.input, 49, self.FOLLOW_49_in_withStatement931)
                if self._state.backtracking == 0:

                    string_literal172_tree = self._adaptor.createWithPayload(string_literal172)
                    self._adaptor.addChild(root_0, string_literal172_tree)

                # /home/buffer/antlr/JavaScript.g:158:13: ( LT )*
                while True: #loop79
                    alt79 = 2
                    LA79_0 = self.input.LA(1)

                    if (LA79_0 == LT) :
                        alt79 = 1


                    if alt79 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT173=self.match(self.input, LT, self.FOLLOW_LT_in_withStatement933)


                    else:
                        break #loop79
                char_literal174=self.match(self.input, 32, self.FOLLOW_32_in_withStatement937)
                if self._state.backtracking == 0:

                    char_literal174_tree = self._adaptor.createWithPayload(char_literal174)
                    self._adaptor.addChild(root_0, char_literal174_tree)

                # /home/buffer/antlr/JavaScript.g:158:22: ( LT )*
                while True: #loop80
                    alt80 = 2
                    LA80_0 = self.input.LA(1)

                    if (LA80_0 == LT) :
                        alt80 = 1


                    if alt80 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT175=self.match(self.input, LT, self.FOLLOW_LT_in_withStatement939)


                    else:
                        break #loop80
                self._state.following.append(self.FOLLOW_expression_in_withStatement943)
                expression176 = self.expression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, expression176.tree)
                # /home/buffer/antlr/JavaScript.g:158:38: ( LT )*
                while True: #loop81
                    alt81 = 2
                    LA81_0 = self.input.LA(1)

                    if (LA81_0 == LT) :
                        alt81 = 1


                    if alt81 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT177=self.match(self.input, LT, self.FOLLOW_LT_in_withStatement945)


                    else:
                        break #loop81
                char_literal178=self.match(self.input, 34, self.FOLLOW_34_in_withStatement949)
                if self._state.backtracking == 0:

                    char_literal178_tree = self._adaptor.createWithPayload(char_literal178)
                    self._adaptor.addChild(root_0, char_literal178_tree)

                # /home/buffer/antlr/JavaScript.g:158:47: ( LT )*
                while True: #loop82
                    alt82 = 2
                    LA82_0 = self.input.LA(1)

                    if (LA82_0 == LT) :
                        alt82 = 1


                    if alt82 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT179=self.match(self.input, LT, self.FOLLOW_LT_in_withStatement951)


                    else:
                        break #loop82
                self._state.following.append(self.FOLLOW_statement_in_withStatement955)
                statement180 = self.statement()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, statement180.tree)



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 31, withStatement_StartIndex, success)

            pass
        return retval

    # $ANTLR end "withStatement"

    class labelledStatement_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.labelledStatement_return, self).__init__()

            self.tree = None




    # $ANTLR start "labelledStatement"
    # /home/buffer/antlr/JavaScript.g:161:1: labelledStatement : Identifier ( LT )* ':' ( LT )* statement ;
    def labelledStatement(self, ):

        retval = self.labelledStatement_return()
        retval.start = self.input.LT(1)
        labelledStatement_StartIndex = self.input.index()
        root_0 = None

        Identifier181 = None
        LT182 = None
        char_literal183 = None
        LT184 = None
        statement185 = None


        Identifier181_tree = None
        LT182_tree = None
        char_literal183_tree = None
        LT184_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 32):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:162:2: ( Identifier ( LT )* ':' ( LT )* statement )
                # /home/buffer/antlr/JavaScript.g:162:4: Identifier ( LT )* ':' ( LT )* statement
                pass 
                root_0 = self._adaptor.nil()

                Identifier181=self.match(self.input, Identifier, self.FOLLOW_Identifier_in_labelledStatement966)
                if self._state.backtracking == 0:

                    Identifier181_tree = self._adaptor.createWithPayload(Identifier181)
                    self._adaptor.addChild(root_0, Identifier181_tree)

                # /home/buffer/antlr/JavaScript.g:162:17: ( LT )*
                while True: #loop83
                    alt83 = 2
                    LA83_0 = self.input.LA(1)

                    if (LA83_0 == LT) :
                        alt83 = 1


                    if alt83 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT182=self.match(self.input, LT, self.FOLLOW_LT_in_labelledStatement968)


                    else:
                        break #loop83
                char_literal183=self.match(self.input, 50, self.FOLLOW_50_in_labelledStatement972)
                if self._state.backtracking == 0:

                    char_literal183_tree = self._adaptor.createWithPayload(char_literal183)
                    self._adaptor.addChild(root_0, char_literal183_tree)

                # /home/buffer/antlr/JavaScript.g:162:26: ( LT )*
                while True: #loop84
                    alt84 = 2
                    LA84_0 = self.input.LA(1)

                    if (LA84_0 == LT) :
                        alt84 = 1


                    if alt84 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT184=self.match(self.input, LT, self.FOLLOW_LT_in_labelledStatement974)


                    else:
                        break #loop84
                self._state.following.append(self.FOLLOW_statement_in_labelledStatement978)
                statement185 = self.statement()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, statement185.tree)



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 32, labelledStatement_StartIndex, success)

            pass
        return retval

    # $ANTLR end "labelledStatement"

    class switchStatement_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.switchStatement_return, self).__init__()

            self.tree = None




    # $ANTLR start "switchStatement"
    # /home/buffer/antlr/JavaScript.g:165:1: switchStatement : 'switch' ( LT )* '(' ( LT )* expression ( LT )* ')' ( LT )* caseBlock ;
    def switchStatement(self, ):

        retval = self.switchStatement_return()
        retval.start = self.input.LT(1)
        switchStatement_StartIndex = self.input.index()
        root_0 = None

        string_literal186 = None
        LT187 = None
        char_literal188 = None
        LT189 = None
        LT191 = None
        char_literal192 = None
        LT193 = None
        expression190 = None

        caseBlock194 = None


        string_literal186_tree = None
        LT187_tree = None
        char_literal188_tree = None
        LT189_tree = None
        LT191_tree = None
        char_literal192_tree = None
        LT193_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 33):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:166:2: ( 'switch' ( LT )* '(' ( LT )* expression ( LT )* ')' ( LT )* caseBlock )
                # /home/buffer/antlr/JavaScript.g:166:4: 'switch' ( LT )* '(' ( LT )* expression ( LT )* ')' ( LT )* caseBlock
                pass 
                root_0 = self._adaptor.nil()

                string_literal186=self.match(self.input, 51, self.FOLLOW_51_in_switchStatement990)
                if self._state.backtracking == 0:

                    string_literal186_tree = self._adaptor.createWithPayload(string_literal186)
                    self._adaptor.addChild(root_0, string_literal186_tree)

                # /home/buffer/antlr/JavaScript.g:166:15: ( LT )*
                while True: #loop85
                    alt85 = 2
                    LA85_0 = self.input.LA(1)

                    if (LA85_0 == LT) :
                        alt85 = 1


                    if alt85 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT187=self.match(self.input, LT, self.FOLLOW_LT_in_switchStatement992)


                    else:
                        break #loop85
                char_literal188=self.match(self.input, 32, self.FOLLOW_32_in_switchStatement996)
                if self._state.backtracking == 0:

                    char_literal188_tree = self._adaptor.createWithPayload(char_literal188)
                    self._adaptor.addChild(root_0, char_literal188_tree)

                # /home/buffer/antlr/JavaScript.g:166:24: ( LT )*
                while True: #loop86
                    alt86 = 2
                    LA86_0 = self.input.LA(1)

                    if (LA86_0 == LT) :
                        alt86 = 1


                    if alt86 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT189=self.match(self.input, LT, self.FOLLOW_LT_in_switchStatement998)


                    else:
                        break #loop86
                self._state.following.append(self.FOLLOW_expression_in_switchStatement1002)
                expression190 = self.expression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, expression190.tree)
                # /home/buffer/antlr/JavaScript.g:166:40: ( LT )*
                while True: #loop87
                    alt87 = 2
                    LA87_0 = self.input.LA(1)

                    if (LA87_0 == LT) :
                        alt87 = 1


                    if alt87 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT191=self.match(self.input, LT, self.FOLLOW_LT_in_switchStatement1004)


                    else:
                        break #loop87
                char_literal192=self.match(self.input, 34, self.FOLLOW_34_in_switchStatement1008)
                if self._state.backtracking == 0:

                    char_literal192_tree = self._adaptor.createWithPayload(char_literal192)
                    self._adaptor.addChild(root_0, char_literal192_tree)

                # /home/buffer/antlr/JavaScript.g:166:49: ( LT )*
                while True: #loop88
                    alt88 = 2
                    LA88_0 = self.input.LA(1)

                    if (LA88_0 == LT) :
                        alt88 = 1


                    if alt88 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT193=self.match(self.input, LT, self.FOLLOW_LT_in_switchStatement1010)


                    else:
                        break #loop88
                self._state.following.append(self.FOLLOW_caseBlock_in_switchStatement1014)
                caseBlock194 = self.caseBlock()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, caseBlock194.tree)



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 33, switchStatement_StartIndex, success)

            pass
        return retval

    # $ANTLR end "switchStatement"

    class caseBlock_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.caseBlock_return, self).__init__()

            self.tree = None




    # $ANTLR start "caseBlock"
    # /home/buffer/antlr/JavaScript.g:169:1: caseBlock : '{' ( ( LT )* caseClause )* ( ( LT )* defaultClause ( ( LT )* caseClause )* )? ( LT )* '}' ;
    def caseBlock(self, ):

        retval = self.caseBlock_return()
        retval.start = self.input.LT(1)
        caseBlock_StartIndex = self.input.index()
        root_0 = None

        char_literal195 = None
        LT196 = None
        LT198 = None
        LT200 = None
        LT202 = None
        char_literal203 = None
        caseClause197 = None

        defaultClause199 = None

        caseClause201 = None


        char_literal195_tree = None
        LT196_tree = None
        LT198_tree = None
        LT200_tree = None
        LT202_tree = None
        char_literal203_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 34):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:170:2: ( '{' ( ( LT )* caseClause )* ( ( LT )* defaultClause ( ( LT )* caseClause )* )? ( LT )* '}' )
                # /home/buffer/antlr/JavaScript.g:170:4: '{' ( ( LT )* caseClause )* ( ( LT )* defaultClause ( ( LT )* caseClause )* )? ( LT )* '}'
                pass 
                root_0 = self._adaptor.nil()

                char_literal195=self.match(self.input, 35, self.FOLLOW_35_in_caseBlock1026)
                if self._state.backtracking == 0:

                    char_literal195_tree = self._adaptor.createWithPayload(char_literal195)
                    self._adaptor.addChild(root_0, char_literal195_tree)

                # /home/buffer/antlr/JavaScript.g:170:8: ( ( LT )* caseClause )*
                while True: #loop90
                    alt90 = 2
                    alt90 = self.dfa90.predict(self.input)
                    if alt90 == 1:
                        # /home/buffer/antlr/JavaScript.g:170:9: ( LT )* caseClause
                        pass 
                        # /home/buffer/antlr/JavaScript.g:170:11: ( LT )*
                        while True: #loop89
                            alt89 = 2
                            LA89_0 = self.input.LA(1)

                            if (LA89_0 == LT) :
                                alt89 = 1


                            if alt89 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT196=self.match(self.input, LT, self.FOLLOW_LT_in_caseBlock1029)


                            else:
                                break #loop89
                        self._state.following.append(self.FOLLOW_caseClause_in_caseBlock1033)
                        caseClause197 = self.caseClause()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, caseClause197.tree)


                    else:
                        break #loop90
                # /home/buffer/antlr/JavaScript.g:170:27: ( ( LT )* defaultClause ( ( LT )* caseClause )* )?
                alt94 = 2
                alt94 = self.dfa94.predict(self.input)
                if alt94 == 1:
                    # /home/buffer/antlr/JavaScript.g:170:28: ( LT )* defaultClause ( ( LT )* caseClause )*
                    pass 
                    # /home/buffer/antlr/JavaScript.g:170:30: ( LT )*
                    while True: #loop91
                        alt91 = 2
                        LA91_0 = self.input.LA(1)

                        if (LA91_0 == LT) :
                            alt91 = 1


                        if alt91 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT198=self.match(self.input, LT, self.FOLLOW_LT_in_caseBlock1038)


                        else:
                            break #loop91
                    self._state.following.append(self.FOLLOW_defaultClause_in_caseBlock1042)
                    defaultClause199 = self.defaultClause()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, defaultClause199.tree)
                    # /home/buffer/antlr/JavaScript.g:170:47: ( ( LT )* caseClause )*
                    while True: #loop93
                        alt93 = 2
                        alt93 = self.dfa93.predict(self.input)
                        if alt93 == 1:
                            # /home/buffer/antlr/JavaScript.g:170:48: ( LT )* caseClause
                            pass 
                            # /home/buffer/antlr/JavaScript.g:170:50: ( LT )*
                            while True: #loop92
                                alt92 = 2
                                LA92_0 = self.input.LA(1)

                                if (LA92_0 == LT) :
                                    alt92 = 1


                                if alt92 == 1:
                                    # /home/buffer/antlr/JavaScript.g:0:0: LT
                                    pass 
                                    LT200=self.match(self.input, LT, self.FOLLOW_LT_in_caseBlock1045)


                                else:
                                    break #loop92
                            self._state.following.append(self.FOLLOW_caseClause_in_caseBlock1049)
                            caseClause201 = self.caseClause()

                            self._state.following.pop()
                            if self._state.backtracking == 0:
                                self._adaptor.addChild(root_0, caseClause201.tree)


                        else:
                            break #loop93



                # /home/buffer/antlr/JavaScript.g:170:70: ( LT )*
                while True: #loop95
                    alt95 = 2
                    LA95_0 = self.input.LA(1)

                    if (LA95_0 == LT) :
                        alt95 = 1


                    if alt95 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT202=self.match(self.input, LT, self.FOLLOW_LT_in_caseBlock1055)


                    else:
                        break #loop95
                char_literal203=self.match(self.input, 36, self.FOLLOW_36_in_caseBlock1059)
                if self._state.backtracking == 0:

                    char_literal203_tree = self._adaptor.createWithPayload(char_literal203)
                    self._adaptor.addChild(root_0, char_literal203_tree)




                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 34, caseBlock_StartIndex, success)

            pass
        return retval

    # $ANTLR end "caseBlock"

    class caseClause_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.caseClause_return, self).__init__()

            self.tree = None




    # $ANTLR start "caseClause"
    # /home/buffer/antlr/JavaScript.g:173:1: caseClause : 'case' ( LT )* expression ( LT )* ':' ( LT )* ( statementList )? ;
    def caseClause(self, ):

        retval = self.caseClause_return()
        retval.start = self.input.LT(1)
        caseClause_StartIndex = self.input.index()
        root_0 = None

        string_literal204 = None
        LT205 = None
        LT207 = None
        char_literal208 = None
        LT209 = None
        expression206 = None

        statementList210 = None


        string_literal204_tree = None
        LT205_tree = None
        LT207_tree = None
        char_literal208_tree = None
        LT209_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 35):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:174:2: ( 'case' ( LT )* expression ( LT )* ':' ( LT )* ( statementList )? )
                # /home/buffer/antlr/JavaScript.g:174:4: 'case' ( LT )* expression ( LT )* ':' ( LT )* ( statementList )?
                pass 
                root_0 = self._adaptor.nil()

                string_literal204=self.match(self.input, 52, self.FOLLOW_52_in_caseClause1070)
                if self._state.backtracking == 0:

                    string_literal204_tree = self._adaptor.createWithPayload(string_literal204)
                    self._adaptor.addChild(root_0, string_literal204_tree)

                # /home/buffer/antlr/JavaScript.g:174:13: ( LT )*
                while True: #loop96
                    alt96 = 2
                    LA96_0 = self.input.LA(1)

                    if (LA96_0 == LT) :
                        alt96 = 1


                    if alt96 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT205=self.match(self.input, LT, self.FOLLOW_LT_in_caseClause1072)


                    else:
                        break #loop96
                self._state.following.append(self.FOLLOW_expression_in_caseClause1076)
                expression206 = self.expression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, expression206.tree)
                # /home/buffer/antlr/JavaScript.g:174:29: ( LT )*
                while True: #loop97
                    alt97 = 2
                    LA97_0 = self.input.LA(1)

                    if (LA97_0 == LT) :
                        alt97 = 1


                    if alt97 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT207=self.match(self.input, LT, self.FOLLOW_LT_in_caseClause1078)


                    else:
                        break #loop97
                char_literal208=self.match(self.input, 50, self.FOLLOW_50_in_caseClause1082)
                if self._state.backtracking == 0:

                    char_literal208_tree = self._adaptor.createWithPayload(char_literal208)
                    self._adaptor.addChild(root_0, char_literal208_tree)

                # /home/buffer/antlr/JavaScript.g:174:38: ( LT )*
                while True: #loop98
                    alt98 = 2
                    LA98_0 = self.input.LA(1)

                    if (LA98_0 == LT) :
                        LA98_2 = self.input.LA(2)

                        if (self.synpred118_JavaScript()) :
                            alt98 = 1




                    if alt98 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT209=self.match(self.input, LT, self.FOLLOW_LT_in_caseClause1084)


                    else:
                        break #loop98
                # /home/buffer/antlr/JavaScript.g:174:41: ( statementList )?
                alt99 = 2
                LA99_0 = self.input.LA(1)

                if ((Identifier <= LA99_0 <= NumericLiteral) or (31 <= LA99_0 <= 32) or LA99_0 == 35 or (37 <= LA99_0 <= 38) or LA99_0 == 40 or (42 <= LA99_0 <= 44) or (46 <= LA99_0 <= 49) or LA99_0 == 51 or (54 <= LA99_0 <= 55) or (58 <= LA99_0 <= 59) or (91 <= LA99_0 <= 92) or (96 <= LA99_0 <= 106)) :
                    alt99 = 1
                if alt99 == 1:
                    # /home/buffer/antlr/JavaScript.g:0:0: statementList
                    pass 
                    self._state.following.append(self.FOLLOW_statementList_in_caseClause1088)
                    statementList210 = self.statementList()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, statementList210.tree)






                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 35, caseClause_StartIndex, success)

            pass
        return retval

    # $ANTLR end "caseClause"

    class defaultClause_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.defaultClause_return, self).__init__()

            self.tree = None




    # $ANTLR start "defaultClause"
    # /home/buffer/antlr/JavaScript.g:177:1: defaultClause : 'default' ( LT )* ':' ( LT )* ( statementList )? ;
    def defaultClause(self, ):

        retval = self.defaultClause_return()
        retval.start = self.input.LT(1)
        defaultClause_StartIndex = self.input.index()
        root_0 = None

        string_literal211 = None
        LT212 = None
        char_literal213 = None
        LT214 = None
        statementList215 = None


        string_literal211_tree = None
        LT212_tree = None
        char_literal213_tree = None
        LT214_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 36):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:178:2: ( 'default' ( LT )* ':' ( LT )* ( statementList )? )
                # /home/buffer/antlr/JavaScript.g:178:4: 'default' ( LT )* ':' ( LT )* ( statementList )?
                pass 
                root_0 = self._adaptor.nil()

                string_literal211=self.match(self.input, 53, self.FOLLOW_53_in_defaultClause1101)
                if self._state.backtracking == 0:

                    string_literal211_tree = self._adaptor.createWithPayload(string_literal211)
                    self._adaptor.addChild(root_0, string_literal211_tree)

                # /home/buffer/antlr/JavaScript.g:178:16: ( LT )*
                while True: #loop100
                    alt100 = 2
                    LA100_0 = self.input.LA(1)

                    if (LA100_0 == LT) :
                        alt100 = 1


                    if alt100 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT212=self.match(self.input, LT, self.FOLLOW_LT_in_defaultClause1103)


                    else:
                        break #loop100
                char_literal213=self.match(self.input, 50, self.FOLLOW_50_in_defaultClause1107)
                if self._state.backtracking == 0:

                    char_literal213_tree = self._adaptor.createWithPayload(char_literal213)
                    self._adaptor.addChild(root_0, char_literal213_tree)

                # /home/buffer/antlr/JavaScript.g:178:25: ( LT )*
                while True: #loop101
                    alt101 = 2
                    LA101_0 = self.input.LA(1)

                    if (LA101_0 == LT) :
                        LA101_2 = self.input.LA(2)

                        if (self.synpred121_JavaScript()) :
                            alt101 = 1




                    if alt101 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT214=self.match(self.input, LT, self.FOLLOW_LT_in_defaultClause1109)


                    else:
                        break #loop101
                # /home/buffer/antlr/JavaScript.g:178:28: ( statementList )?
                alt102 = 2
                LA102_0 = self.input.LA(1)

                if ((Identifier <= LA102_0 <= NumericLiteral) or (31 <= LA102_0 <= 32) or LA102_0 == 35 or (37 <= LA102_0 <= 38) or LA102_0 == 40 or (42 <= LA102_0 <= 44) or (46 <= LA102_0 <= 49) or LA102_0 == 51 or (54 <= LA102_0 <= 55) or (58 <= LA102_0 <= 59) or (91 <= LA102_0 <= 92) or (96 <= LA102_0 <= 106)) :
                    alt102 = 1
                if alt102 == 1:
                    # /home/buffer/antlr/JavaScript.g:0:0: statementList
                    pass 
                    self._state.following.append(self.FOLLOW_statementList_in_defaultClause1113)
                    statementList215 = self.statementList()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, statementList215.tree)






                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 36, defaultClause_StartIndex, success)

            pass
        return retval

    # $ANTLR end "defaultClause"

    class throwStatement_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.throwStatement_return, self).__init__()

            self.tree = None




    # $ANTLR start "throwStatement"
    # /home/buffer/antlr/JavaScript.g:181:1: throwStatement : 'throw' expression ( LT | ';' ) ;
    def throwStatement(self, ):

        retval = self.throwStatement_return()
        retval.start = self.input.LT(1)
        throwStatement_StartIndex = self.input.index()
        root_0 = None

        string_literal216 = None
        set218 = None
        expression217 = None


        string_literal216_tree = None
        set218_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 37):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:182:2: ( 'throw' expression ( LT | ';' ) )
                # /home/buffer/antlr/JavaScript.g:182:4: 'throw' expression ( LT | ';' )
                pass 
                root_0 = self._adaptor.nil()

                string_literal216=self.match(self.input, 54, self.FOLLOW_54_in_throwStatement1126)
                if self._state.backtracking == 0:

                    string_literal216_tree = self._adaptor.createWithPayload(string_literal216)
                    self._adaptor.addChild(root_0, string_literal216_tree)

                self._state.following.append(self.FOLLOW_expression_in_throwStatement1128)
                expression217 = self.expression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, expression217.tree)
                set218 = self.input.LT(1)
                if self.input.LA(1) == LT or self.input.LA(1) == 38:
                    self.input.consume()
                    self._state.errorRecovery = False

                else:
                    if self._state.backtracking > 0:
                        raise BacktrackingFailed

                    mse = MismatchedSetException(None, self.input)
                    raise mse





                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 37, throwStatement_StartIndex, success)

            pass
        return retval

    # $ANTLR end "throwStatement"

    class tryStatement_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.tryStatement_return, self).__init__()

            self.tree = None




    # $ANTLR start "tryStatement"
    # /home/buffer/antlr/JavaScript.g:185:1: tryStatement : 'try' ( LT )* statementBlock ( LT )* ( finallyClause | catchClause ( ( LT )* finallyClause )? ) ;
    def tryStatement(self, ):

        retval = self.tryStatement_return()
        retval.start = self.input.LT(1)
        tryStatement_StartIndex = self.input.index()
        root_0 = None

        string_literal219 = None
        LT220 = None
        LT222 = None
        LT225 = None
        statementBlock221 = None

        finallyClause223 = None

        catchClause224 = None

        finallyClause226 = None


        string_literal219_tree = None
        LT220_tree = None
        LT222_tree = None
        LT225_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 38):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:186:2: ( 'try' ( LT )* statementBlock ( LT )* ( finallyClause | catchClause ( ( LT )* finallyClause )? ) )
                # /home/buffer/antlr/JavaScript.g:186:4: 'try' ( LT )* statementBlock ( LT )* ( finallyClause | catchClause ( ( LT )* finallyClause )? )
                pass 
                root_0 = self._adaptor.nil()

                string_literal219=self.match(self.input, 55, self.FOLLOW_55_in_tryStatement1148)
                if self._state.backtracking == 0:

                    string_literal219_tree = self._adaptor.createWithPayload(string_literal219)
                    self._adaptor.addChild(root_0, string_literal219_tree)

                # /home/buffer/antlr/JavaScript.g:186:12: ( LT )*
                while True: #loop103
                    alt103 = 2
                    LA103_0 = self.input.LA(1)

                    if (LA103_0 == LT) :
                        alt103 = 1


                    if alt103 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT220=self.match(self.input, LT, self.FOLLOW_LT_in_tryStatement1150)


                    else:
                        break #loop103
                self._state.following.append(self.FOLLOW_statementBlock_in_tryStatement1154)
                statementBlock221 = self.statementBlock()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, statementBlock221.tree)
                # /home/buffer/antlr/JavaScript.g:186:32: ( LT )*
                while True: #loop104
                    alt104 = 2
                    LA104_0 = self.input.LA(1)

                    if (LA104_0 == LT) :
                        alt104 = 1


                    if alt104 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT222=self.match(self.input, LT, self.FOLLOW_LT_in_tryStatement1156)


                    else:
                        break #loop104
                # /home/buffer/antlr/JavaScript.g:186:35: ( finallyClause | catchClause ( ( LT )* finallyClause )? )
                alt107 = 2
                LA107_0 = self.input.LA(1)

                if (LA107_0 == 57) :
                    alt107 = 1
                elif (LA107_0 == 56) :
                    alt107 = 2
                else:
                    if self._state.backtracking > 0:
                        raise BacktrackingFailed

                    nvae = NoViableAltException("", 107, 0, self.input)

                    raise nvae

                if alt107 == 1:
                    # /home/buffer/antlr/JavaScript.g:186:36: finallyClause
                    pass 
                    self._state.following.append(self.FOLLOW_finallyClause_in_tryStatement1161)
                    finallyClause223 = self.finallyClause()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, finallyClause223.tree)


                elif alt107 == 2:
                    # /home/buffer/antlr/JavaScript.g:186:52: catchClause ( ( LT )* finallyClause )?
                    pass 
                    self._state.following.append(self.FOLLOW_catchClause_in_tryStatement1165)
                    catchClause224 = self.catchClause()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, catchClause224.tree)
                    # /home/buffer/antlr/JavaScript.g:186:64: ( ( LT )* finallyClause )?
                    alt106 = 2
                    alt106 = self.dfa106.predict(self.input)
                    if alt106 == 1:
                        # /home/buffer/antlr/JavaScript.g:186:65: ( LT )* finallyClause
                        pass 
                        # /home/buffer/antlr/JavaScript.g:186:67: ( LT )*
                        while True: #loop105
                            alt105 = 2
                            LA105_0 = self.input.LA(1)

                            if (LA105_0 == LT) :
                                alt105 = 1


                            if alt105 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT225=self.match(self.input, LT, self.FOLLOW_LT_in_tryStatement1168)


                            else:
                                break #loop105
                        self._state.following.append(self.FOLLOW_finallyClause_in_tryStatement1172)
                        finallyClause226 = self.finallyClause()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, finallyClause226.tree)









                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 38, tryStatement_StartIndex, success)

            pass
        return retval

    # $ANTLR end "tryStatement"

    class catchClause_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.catchClause_return, self).__init__()

            self.tree = None




    # $ANTLR start "catchClause"
    # /home/buffer/antlr/JavaScript.g:189:1: catchClause : 'catch' ( LT )* '(' ( LT )* Identifier ( LT )* ')' ( LT )* statementBlock ;
    def catchClause(self, ):

        retval = self.catchClause_return()
        retval.start = self.input.LT(1)
        catchClause_StartIndex = self.input.index()
        root_0 = None

        string_literal227 = None
        LT228 = None
        char_literal229 = None
        LT230 = None
        Identifier231 = None
        LT232 = None
        char_literal233 = None
        LT234 = None
        statementBlock235 = None


        string_literal227_tree = None
        LT228_tree = None
        char_literal229_tree = None
        LT230_tree = None
        Identifier231_tree = None
        LT232_tree = None
        char_literal233_tree = None
        LT234_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 39):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:190:2: ( 'catch' ( LT )* '(' ( LT )* Identifier ( LT )* ')' ( LT )* statementBlock )
                # /home/buffer/antlr/JavaScript.g:190:4: 'catch' ( LT )* '(' ( LT )* Identifier ( LT )* ')' ( LT )* statementBlock
                pass 
                root_0 = self._adaptor.nil()

                string_literal227=self.match(self.input, 56, self.FOLLOW_56_in_catchClause1193)
                if self._state.backtracking == 0:

                    string_literal227_tree = self._adaptor.createWithPayload(string_literal227)
                    self._adaptor.addChild(root_0, string_literal227_tree)

                # /home/buffer/antlr/JavaScript.g:190:14: ( LT )*
                while True: #loop108
                    alt108 = 2
                    LA108_0 = self.input.LA(1)

                    if (LA108_0 == LT) :
                        alt108 = 1


                    if alt108 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT228=self.match(self.input, LT, self.FOLLOW_LT_in_catchClause1195)


                    else:
                        break #loop108
                char_literal229=self.match(self.input, 32, self.FOLLOW_32_in_catchClause1199)
                if self._state.backtracking == 0:

                    char_literal229_tree = self._adaptor.createWithPayload(char_literal229)
                    self._adaptor.addChild(root_0, char_literal229_tree)

                # /home/buffer/antlr/JavaScript.g:190:23: ( LT )*
                while True: #loop109
                    alt109 = 2
                    LA109_0 = self.input.LA(1)

                    if (LA109_0 == LT) :
                        alt109 = 1


                    if alt109 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT230=self.match(self.input, LT, self.FOLLOW_LT_in_catchClause1201)


                    else:
                        break #loop109
                Identifier231=self.match(self.input, Identifier, self.FOLLOW_Identifier_in_catchClause1205)
                if self._state.backtracking == 0:

                    Identifier231_tree = self._adaptor.createWithPayload(Identifier231)
                    self._adaptor.addChild(root_0, Identifier231_tree)

                # /home/buffer/antlr/JavaScript.g:190:39: ( LT )*
                while True: #loop110
                    alt110 = 2
                    LA110_0 = self.input.LA(1)

                    if (LA110_0 == LT) :
                        alt110 = 1


                    if alt110 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT232=self.match(self.input, LT, self.FOLLOW_LT_in_catchClause1207)


                    else:
                        break #loop110
                char_literal233=self.match(self.input, 34, self.FOLLOW_34_in_catchClause1211)
                if self._state.backtracking == 0:

                    char_literal233_tree = self._adaptor.createWithPayload(char_literal233)
                    self._adaptor.addChild(root_0, char_literal233_tree)

                # /home/buffer/antlr/JavaScript.g:190:48: ( LT )*
                while True: #loop111
                    alt111 = 2
                    LA111_0 = self.input.LA(1)

                    if (LA111_0 == LT) :
                        alt111 = 1


                    if alt111 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT234=self.match(self.input, LT, self.FOLLOW_LT_in_catchClause1213)


                    else:
                        break #loop111
                self._state.following.append(self.FOLLOW_statementBlock_in_catchClause1217)
                statementBlock235 = self.statementBlock()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, statementBlock235.tree)



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 39, catchClause_StartIndex, success)

            pass
        return retval

    # $ANTLR end "catchClause"

    class finallyClause_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.finallyClause_return, self).__init__()

            self.tree = None




    # $ANTLR start "finallyClause"
    # /home/buffer/antlr/JavaScript.g:193:1: finallyClause : 'finally' ( LT )* statementBlock ;
    def finallyClause(self, ):

        retval = self.finallyClause_return()
        retval.start = self.input.LT(1)
        finallyClause_StartIndex = self.input.index()
        root_0 = None

        string_literal236 = None
        LT237 = None
        statementBlock238 = None


        string_literal236_tree = None
        LT237_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 40):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:194:2: ( 'finally' ( LT )* statementBlock )
                # /home/buffer/antlr/JavaScript.g:194:4: 'finally' ( LT )* statementBlock
                pass 
                root_0 = self._adaptor.nil()

                string_literal236=self.match(self.input, 57, self.FOLLOW_57_in_finallyClause1229)
                if self._state.backtracking == 0:

                    string_literal236_tree = self._adaptor.createWithPayload(string_literal236)
                    self._adaptor.addChild(root_0, string_literal236_tree)

                # /home/buffer/antlr/JavaScript.g:194:16: ( LT )*
                while True: #loop112
                    alt112 = 2
                    LA112_0 = self.input.LA(1)

                    if (LA112_0 == LT) :
                        alt112 = 1


                    if alt112 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT237=self.match(self.input, LT, self.FOLLOW_LT_in_finallyClause1231)


                    else:
                        break #loop112
                self._state.following.append(self.FOLLOW_statementBlock_in_finallyClause1235)
                statementBlock238 = self.statementBlock()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, statementBlock238.tree)



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 40, finallyClause_StartIndex, success)

            pass
        return retval

    # $ANTLR end "finallyClause"

    class expression_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.expression_return, self).__init__()

            self.tree = None




    # $ANTLR start "expression"
    # /home/buffer/antlr/JavaScript.g:198:1: expression : assignmentExpression ( ( LT )* ',' ( LT )* assignmentExpression )* ;
    def expression(self, ):

        retval = self.expression_return()
        retval.start = self.input.LT(1)
        expression_StartIndex = self.input.index()
        root_0 = None

        LT240 = None
        char_literal241 = None
        LT242 = None
        assignmentExpression239 = None

        assignmentExpression243 = None


        LT240_tree = None
        char_literal241_tree = None
        LT242_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 41):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:199:2: ( assignmentExpression ( ( LT )* ',' ( LT )* assignmentExpression )* )
                # /home/buffer/antlr/JavaScript.g:199:4: assignmentExpression ( ( LT )* ',' ( LT )* assignmentExpression )*
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_assignmentExpression_in_expression1247)
                assignmentExpression239 = self.assignmentExpression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, assignmentExpression239.tree)
                # /home/buffer/antlr/JavaScript.g:199:25: ( ( LT )* ',' ( LT )* assignmentExpression )*
                while True: #loop115
                    alt115 = 2
                    alt115 = self.dfa115.predict(self.input)
                    if alt115 == 1:
                        # /home/buffer/antlr/JavaScript.g:199:26: ( LT )* ',' ( LT )* assignmentExpression
                        pass 
                        # /home/buffer/antlr/JavaScript.g:199:28: ( LT )*
                        while True: #loop113
                            alt113 = 2
                            LA113_0 = self.input.LA(1)

                            if (LA113_0 == LT) :
                                alt113 = 1


                            if alt113 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT240=self.match(self.input, LT, self.FOLLOW_LT_in_expression1250)


                            else:
                                break #loop113
                        char_literal241=self.match(self.input, 33, self.FOLLOW_33_in_expression1254)
                        if self._state.backtracking == 0:

                            char_literal241_tree = self._adaptor.createWithPayload(char_literal241)
                            self._adaptor.addChild(root_0, char_literal241_tree)

                        # /home/buffer/antlr/JavaScript.g:199:37: ( LT )*
                        while True: #loop114
                            alt114 = 2
                            LA114_0 = self.input.LA(1)

                            if (LA114_0 == LT) :
                                alt114 = 1


                            if alt114 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT242=self.match(self.input, LT, self.FOLLOW_LT_in_expression1256)


                            else:
                                break #loop114
                        self._state.following.append(self.FOLLOW_assignmentExpression_in_expression1260)
                        assignmentExpression243 = self.assignmentExpression()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, assignmentExpression243.tree)


                    else:
                        break #loop115



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 41, expression_StartIndex, success)

            pass
        return retval

    # $ANTLR end "expression"

    class expressionNoIn_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.expressionNoIn_return, self).__init__()

            self.tree = None




    # $ANTLR start "expressionNoIn"
    # /home/buffer/antlr/JavaScript.g:202:1: expressionNoIn : assignmentExpressionNoIn ( ( LT )* ',' ( LT )* assignmentExpressionNoIn )* ;
    def expressionNoIn(self, ):

        retval = self.expressionNoIn_return()
        retval.start = self.input.LT(1)
        expressionNoIn_StartIndex = self.input.index()
        root_0 = None

        LT245 = None
        char_literal246 = None
        LT247 = None
        assignmentExpressionNoIn244 = None

        assignmentExpressionNoIn248 = None


        LT245_tree = None
        char_literal246_tree = None
        LT247_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 42):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:203:2: ( assignmentExpressionNoIn ( ( LT )* ',' ( LT )* assignmentExpressionNoIn )* )
                # /home/buffer/antlr/JavaScript.g:203:4: assignmentExpressionNoIn ( ( LT )* ',' ( LT )* assignmentExpressionNoIn )*
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_assignmentExpressionNoIn_in_expressionNoIn1274)
                assignmentExpressionNoIn244 = self.assignmentExpressionNoIn()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, assignmentExpressionNoIn244.tree)
                # /home/buffer/antlr/JavaScript.g:203:29: ( ( LT )* ',' ( LT )* assignmentExpressionNoIn )*
                while True: #loop118
                    alt118 = 2
                    alt118 = self.dfa118.predict(self.input)
                    if alt118 == 1:
                        # /home/buffer/antlr/JavaScript.g:203:30: ( LT )* ',' ( LT )* assignmentExpressionNoIn
                        pass 
                        # /home/buffer/antlr/JavaScript.g:203:32: ( LT )*
                        while True: #loop116
                            alt116 = 2
                            LA116_0 = self.input.LA(1)

                            if (LA116_0 == LT) :
                                alt116 = 1


                            if alt116 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT245=self.match(self.input, LT, self.FOLLOW_LT_in_expressionNoIn1277)


                            else:
                                break #loop116
                        char_literal246=self.match(self.input, 33, self.FOLLOW_33_in_expressionNoIn1281)
                        if self._state.backtracking == 0:

                            char_literal246_tree = self._adaptor.createWithPayload(char_literal246)
                            self._adaptor.addChild(root_0, char_literal246_tree)

                        # /home/buffer/antlr/JavaScript.g:203:41: ( LT )*
                        while True: #loop117
                            alt117 = 2
                            LA117_0 = self.input.LA(1)

                            if (LA117_0 == LT) :
                                alt117 = 1


                            if alt117 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT247=self.match(self.input, LT, self.FOLLOW_LT_in_expressionNoIn1283)


                            else:
                                break #loop117
                        self._state.following.append(self.FOLLOW_assignmentExpressionNoIn_in_expressionNoIn1287)
                        assignmentExpressionNoIn248 = self.assignmentExpressionNoIn()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, assignmentExpressionNoIn248.tree)


                    else:
                        break #loop118



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 42, expressionNoIn_StartIndex, success)

            pass
        return retval

    # $ANTLR end "expressionNoIn"

    class assignmentExpression_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.assignmentExpression_return, self).__init__()

            self.tree = None




    # $ANTLR start "assignmentExpression"
    # /home/buffer/antlr/JavaScript.g:206:1: assignmentExpression : ( conditionalExpression | leftHandSideExpression ( LT )* assignmentOperator ( LT )* assignmentExpression );
    def assignmentExpression(self, ):

        retval = self.assignmentExpression_return()
        retval.start = self.input.LT(1)
        assignmentExpression_StartIndex = self.input.index()
        root_0 = None

        LT251 = None
        LT253 = None
        conditionalExpression249 = None

        leftHandSideExpression250 = None

        assignmentOperator252 = None

        assignmentExpression254 = None


        LT251_tree = None
        LT253_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 43):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:207:2: ( conditionalExpression | leftHandSideExpression ( LT )* assignmentOperator ( LT )* assignmentExpression )
                alt121 = 2
                alt121 = self.dfa121.predict(self.input)
                if alt121 == 1:
                    # /home/buffer/antlr/JavaScript.g:207:4: conditionalExpression
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_conditionalExpression_in_assignmentExpression1301)
                    conditionalExpression249 = self.conditionalExpression()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, conditionalExpression249.tree)


                elif alt121 == 2:
                    # /home/buffer/antlr/JavaScript.g:208:4: leftHandSideExpression ( LT )* assignmentOperator ( LT )* assignmentExpression
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_leftHandSideExpression_in_assignmentExpression1306)
                    leftHandSideExpression250 = self.leftHandSideExpression()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, leftHandSideExpression250.tree)
                    # /home/buffer/antlr/JavaScript.g:208:29: ( LT )*
                    while True: #loop119
                        alt119 = 2
                        LA119_0 = self.input.LA(1)

                        if (LA119_0 == LT) :
                            alt119 = 1


                        if alt119 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT251=self.match(self.input, LT, self.FOLLOW_LT_in_assignmentExpression1308)


                        else:
                            break #loop119
                    self._state.following.append(self.FOLLOW_assignmentOperator_in_assignmentExpression1312)
                    assignmentOperator252 = self.assignmentOperator()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, assignmentOperator252.tree)
                    # /home/buffer/antlr/JavaScript.g:208:53: ( LT )*
                    while True: #loop120
                        alt120 = 2
                        LA120_0 = self.input.LA(1)

                        if (LA120_0 == LT) :
                            alt120 = 1


                        if alt120 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT253=self.match(self.input, LT, self.FOLLOW_LT_in_assignmentExpression1314)


                        else:
                            break #loop120
                    self._state.following.append(self.FOLLOW_assignmentExpression_in_assignmentExpression1318)
                    assignmentExpression254 = self.assignmentExpression()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, assignmentExpression254.tree)


                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 43, assignmentExpression_StartIndex, success)

            pass
        return retval

    # $ANTLR end "assignmentExpression"

    class assignmentExpressionNoIn_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.assignmentExpressionNoIn_return, self).__init__()

            self.tree = None




    # $ANTLR start "assignmentExpressionNoIn"
    # /home/buffer/antlr/JavaScript.g:211:1: assignmentExpressionNoIn : ( conditionalExpressionNoIn | leftHandSideExpression ( LT )* assignmentOperator ( LT )* assignmentExpressionNoIn );
    def assignmentExpressionNoIn(self, ):

        retval = self.assignmentExpressionNoIn_return()
        retval.start = self.input.LT(1)
        assignmentExpressionNoIn_StartIndex = self.input.index()
        root_0 = None

        LT257 = None
        LT259 = None
        conditionalExpressionNoIn255 = None

        leftHandSideExpression256 = None

        assignmentOperator258 = None

        assignmentExpressionNoIn260 = None


        LT257_tree = None
        LT259_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 44):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:212:2: ( conditionalExpressionNoIn | leftHandSideExpression ( LT )* assignmentOperator ( LT )* assignmentExpressionNoIn )
                alt124 = 2
                alt124 = self.dfa124.predict(self.input)
                if alt124 == 1:
                    # /home/buffer/antlr/JavaScript.g:212:4: conditionalExpressionNoIn
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_conditionalExpressionNoIn_in_assignmentExpressionNoIn1330)
                    conditionalExpressionNoIn255 = self.conditionalExpressionNoIn()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, conditionalExpressionNoIn255.tree)


                elif alt124 == 2:
                    # /home/buffer/antlr/JavaScript.g:213:4: leftHandSideExpression ( LT )* assignmentOperator ( LT )* assignmentExpressionNoIn
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_leftHandSideExpression_in_assignmentExpressionNoIn1335)
                    leftHandSideExpression256 = self.leftHandSideExpression()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, leftHandSideExpression256.tree)
                    # /home/buffer/antlr/JavaScript.g:213:29: ( LT )*
                    while True: #loop122
                        alt122 = 2
                        LA122_0 = self.input.LA(1)

                        if (LA122_0 == LT) :
                            alt122 = 1


                        if alt122 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT257=self.match(self.input, LT, self.FOLLOW_LT_in_assignmentExpressionNoIn1337)


                        else:
                            break #loop122
                    self._state.following.append(self.FOLLOW_assignmentOperator_in_assignmentExpressionNoIn1341)
                    assignmentOperator258 = self.assignmentOperator()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, assignmentOperator258.tree)
                    # /home/buffer/antlr/JavaScript.g:213:53: ( LT )*
                    while True: #loop123
                        alt123 = 2
                        LA123_0 = self.input.LA(1)

                        if (LA123_0 == LT) :
                            alt123 = 1


                        if alt123 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT259=self.match(self.input, LT, self.FOLLOW_LT_in_assignmentExpressionNoIn1343)


                        else:
                            break #loop123
                    self._state.following.append(self.FOLLOW_assignmentExpressionNoIn_in_assignmentExpressionNoIn1347)
                    assignmentExpressionNoIn260 = self.assignmentExpressionNoIn()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, assignmentExpressionNoIn260.tree)


                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 44, assignmentExpressionNoIn_StartIndex, success)

            pass
        return retval

    # $ANTLR end "assignmentExpressionNoIn"

    class leftHandSideExpression_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.leftHandSideExpression_return, self).__init__()

            self.tree = None




    # $ANTLR start "leftHandSideExpression"
    # /home/buffer/antlr/JavaScript.g:216:1: leftHandSideExpression : ( callExpression | newExpression );
    def leftHandSideExpression(self, ):

        retval = self.leftHandSideExpression_return()
        retval.start = self.input.LT(1)
        leftHandSideExpression_StartIndex = self.input.index()
        root_0 = None

        callExpression261 = None

        newExpression262 = None



        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 45):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:217:2: ( callExpression | newExpression )
                alt125 = 2
                alt125 = self.dfa125.predict(self.input)
                if alt125 == 1:
                    # /home/buffer/antlr/JavaScript.g:217:4: callExpression
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_callExpression_in_leftHandSideExpression1359)
                    callExpression261 = self.callExpression()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, callExpression261.tree)


                elif alt125 == 2:
                    # /home/buffer/antlr/JavaScript.g:218:4: newExpression
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_newExpression_in_leftHandSideExpression1364)
                    newExpression262 = self.newExpression()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, newExpression262.tree)


                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 45, leftHandSideExpression_StartIndex, success)

            pass
        return retval

    # $ANTLR end "leftHandSideExpression"

    class newExpression_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.newExpression_return, self).__init__()

            self.tree = None




    # $ANTLR start "newExpression"
    # /home/buffer/antlr/JavaScript.g:221:1: newExpression : ( memberExpression | 'new' ( LT )* newExpression );
    def newExpression(self, ):

        retval = self.newExpression_return()
        retval.start = self.input.LT(1)
        newExpression_StartIndex = self.input.index()
        root_0 = None

        string_literal264 = None
        LT265 = None
        memberExpression263 = None

        newExpression266 = None


        string_literal264_tree = None
        LT265_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 46):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:222:2: ( memberExpression | 'new' ( LT )* newExpression )
                alt127 = 2
                alt127 = self.dfa127.predict(self.input)
                if alt127 == 1:
                    # /home/buffer/antlr/JavaScript.g:222:4: memberExpression
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_memberExpression_in_newExpression1376)
                    memberExpression263 = self.memberExpression()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, memberExpression263.tree)


                elif alt127 == 2:
                    # /home/buffer/antlr/JavaScript.g:223:4: 'new' ( LT )* newExpression
                    pass 
                    root_0 = self._adaptor.nil()

                    string_literal264=self.match(self.input, 58, self.FOLLOW_58_in_newExpression1381)
                    if self._state.backtracking == 0:

                        string_literal264_tree = self._adaptor.createWithPayload(string_literal264)
                        self._adaptor.addChild(root_0, string_literal264_tree)

                    # /home/buffer/antlr/JavaScript.g:223:12: ( LT )*
                    while True: #loop126
                        alt126 = 2
                        LA126_0 = self.input.LA(1)

                        if (LA126_0 == LT) :
                            alt126 = 1


                        if alt126 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT265=self.match(self.input, LT, self.FOLLOW_LT_in_newExpression1383)


                        else:
                            break #loop126
                    self._state.following.append(self.FOLLOW_newExpression_in_newExpression1387)
                    newExpression266 = self.newExpression()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, newExpression266.tree)


                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 46, newExpression_StartIndex, success)

            pass
        return retval

    # $ANTLR end "newExpression"

    class memberExpression_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.memberExpression_return, self).__init__()

            self.tree = None




    # $ANTLR start "memberExpression"
    # /home/buffer/antlr/JavaScript.g:226:1: memberExpression : ( primaryExpression | functionExpression | 'new' ( LT )* memberExpression ( LT )* arguments ) ( ( LT )* memberExpressionSuffix )* ;
    def memberExpression(self, ):

        retval = self.memberExpression_return()
        retval.start = self.input.LT(1)
        memberExpression_StartIndex = self.input.index()
        root_0 = None

        string_literal269 = None
        LT270 = None
        LT272 = None
        LT274 = None
        primaryExpression267 = None

        functionExpression268 = None

        memberExpression271 = None

        arguments273 = None

        memberExpressionSuffix275 = None


        string_literal269_tree = None
        LT270_tree = None
        LT272_tree = None
        LT274_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 47):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:227:2: ( ( primaryExpression | functionExpression | 'new' ( LT )* memberExpression ( LT )* arguments ) ( ( LT )* memberExpressionSuffix )* )
                # /home/buffer/antlr/JavaScript.g:227:4: ( primaryExpression | functionExpression | 'new' ( LT )* memberExpression ( LT )* arguments ) ( ( LT )* memberExpressionSuffix )*
                pass 
                root_0 = self._adaptor.nil()

                # /home/buffer/antlr/JavaScript.g:227:4: ( primaryExpression | functionExpression | 'new' ( LT )* memberExpression ( LT )* arguments )
                alt130 = 3
                LA130 = self.input.LA(1)
                if LA130 == Identifier or LA130 == StringLiteral or LA130 == NumericLiteral or LA130 == 32 or LA130 == 35 or LA130 == 59 or LA130 == 103 or LA130 == 104 or LA130 == 105 or LA130 == 106:
                    alt130 = 1
                elif LA130 == 31:
                    alt130 = 2
                elif LA130 == 58:
                    alt130 = 3
                else:
                    if self._state.backtracking > 0:
                        raise BacktrackingFailed

                    nvae = NoViableAltException("", 130, 0, self.input)

                    raise nvae

                if alt130 == 1:
                    # /home/buffer/antlr/JavaScript.g:227:5: primaryExpression
                    pass 
                    self._state.following.append(self.FOLLOW_primaryExpression_in_memberExpression1400)
                    primaryExpression267 = self.primaryExpression()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, primaryExpression267.tree)


                elif alt130 == 2:
                    # /home/buffer/antlr/JavaScript.g:227:25: functionExpression
                    pass 
                    self._state.following.append(self.FOLLOW_functionExpression_in_memberExpression1404)
                    functionExpression268 = self.functionExpression()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, functionExpression268.tree)


                elif alt130 == 3:
                    # /home/buffer/antlr/JavaScript.g:227:46: 'new' ( LT )* memberExpression ( LT )* arguments
                    pass 
                    string_literal269=self.match(self.input, 58, self.FOLLOW_58_in_memberExpression1408)
                    if self._state.backtracking == 0:

                        string_literal269_tree = self._adaptor.createWithPayload(string_literal269)
                        self._adaptor.addChild(root_0, string_literal269_tree)

                    # /home/buffer/antlr/JavaScript.g:227:54: ( LT )*
                    while True: #loop128
                        alt128 = 2
                        LA128_0 = self.input.LA(1)

                        if (LA128_0 == LT) :
                            alt128 = 1


                        if alt128 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT270=self.match(self.input, LT, self.FOLLOW_LT_in_memberExpression1410)


                        else:
                            break #loop128
                    self._state.following.append(self.FOLLOW_memberExpression_in_memberExpression1414)
                    memberExpression271 = self.memberExpression()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, memberExpression271.tree)
                    # /home/buffer/antlr/JavaScript.g:227:76: ( LT )*
                    while True: #loop129
                        alt129 = 2
                        LA129_0 = self.input.LA(1)

                        if (LA129_0 == LT) :
                            alt129 = 1


                        if alt129 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT272=self.match(self.input, LT, self.FOLLOW_LT_in_memberExpression1416)


                        else:
                            break #loop129
                    self._state.following.append(self.FOLLOW_arguments_in_memberExpression1420)
                    arguments273 = self.arguments()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, arguments273.tree)



                # /home/buffer/antlr/JavaScript.g:227:90: ( ( LT )* memberExpressionSuffix )*
                while True: #loop132
                    alt132 = 2
                    alt132 = self.dfa132.predict(self.input)
                    if alt132 == 1:
                        # /home/buffer/antlr/JavaScript.g:227:91: ( LT )* memberExpressionSuffix
                        pass 
                        # /home/buffer/antlr/JavaScript.g:227:93: ( LT )*
                        while True: #loop131
                            alt131 = 2
                            LA131_0 = self.input.LA(1)

                            if (LA131_0 == LT) :
                                alt131 = 1


                            if alt131 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT274=self.match(self.input, LT, self.FOLLOW_LT_in_memberExpression1424)


                            else:
                                break #loop131
                        self._state.following.append(self.FOLLOW_memberExpressionSuffix_in_memberExpression1428)
                        memberExpressionSuffix275 = self.memberExpressionSuffix()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, memberExpressionSuffix275.tree)


                    else:
                        break #loop132



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 47, memberExpression_StartIndex, success)

            pass
        return retval

    # $ANTLR end "memberExpression"

    class memberExpressionSuffix_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.memberExpressionSuffix_return, self).__init__()

            self.tree = None




    # $ANTLR start "memberExpressionSuffix"
    # /home/buffer/antlr/JavaScript.g:230:1: memberExpressionSuffix : ( indexSuffix | propertyReferenceSuffix );
    def memberExpressionSuffix(self, ):

        retval = self.memberExpressionSuffix_return()
        retval.start = self.input.LT(1)
        memberExpressionSuffix_StartIndex = self.input.index()
        root_0 = None

        indexSuffix276 = None

        propertyReferenceSuffix277 = None



        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 48):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:231:2: ( indexSuffix | propertyReferenceSuffix )
                alt133 = 2
                LA133_0 = self.input.LA(1)

                if (LA133_0 == 59) :
                    alt133 = 1
                elif (LA133_0 == 61) :
                    alt133 = 2
                else:
                    if self._state.backtracking > 0:
                        raise BacktrackingFailed

                    nvae = NoViableAltException("", 133, 0, self.input)

                    raise nvae

                if alt133 == 1:
                    # /home/buffer/antlr/JavaScript.g:231:4: indexSuffix
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_indexSuffix_in_memberExpressionSuffix1442)
                    indexSuffix276 = self.indexSuffix()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, indexSuffix276.tree)


                elif alt133 == 2:
                    # /home/buffer/antlr/JavaScript.g:232:4: propertyReferenceSuffix
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_propertyReferenceSuffix_in_memberExpressionSuffix1447)
                    propertyReferenceSuffix277 = self.propertyReferenceSuffix()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, propertyReferenceSuffix277.tree)


                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 48, memberExpressionSuffix_StartIndex, success)

            pass
        return retval

    # $ANTLR end "memberExpressionSuffix"

    class callExpression_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.callExpression_return, self).__init__()

            self.tree = None




    # $ANTLR start "callExpression"
    # /home/buffer/antlr/JavaScript.g:235:1: callExpression : memberExpression ( LT )* arguments ( ( LT )* callExpressionSuffix )* ;
    def callExpression(self, ):

        retval = self.callExpression_return()
        retval.start = self.input.LT(1)
        callExpression_StartIndex = self.input.index()
        root_0 = None

        LT279 = None
        LT281 = None
        memberExpression278 = None

        arguments280 = None

        callExpressionSuffix282 = None


        LT279_tree = None
        LT281_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 49):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:236:2: ( memberExpression ( LT )* arguments ( ( LT )* callExpressionSuffix )* )
                # /home/buffer/antlr/JavaScript.g:236:4: memberExpression ( LT )* arguments ( ( LT )* callExpressionSuffix )*
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_memberExpression_in_callExpression1458)
                memberExpression278 = self.memberExpression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, memberExpression278.tree)
                # /home/buffer/antlr/JavaScript.g:236:23: ( LT )*
                while True: #loop134
                    alt134 = 2
                    LA134_0 = self.input.LA(1)

                    if (LA134_0 == LT) :
                        alt134 = 1


                    if alt134 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT279=self.match(self.input, LT, self.FOLLOW_LT_in_callExpression1460)


                    else:
                        break #loop134
                self._state.following.append(self.FOLLOW_arguments_in_callExpression1464)
                arguments280 = self.arguments()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, arguments280.tree)
                # /home/buffer/antlr/JavaScript.g:236:36: ( ( LT )* callExpressionSuffix )*
                while True: #loop136
                    alt136 = 2
                    alt136 = self.dfa136.predict(self.input)
                    if alt136 == 1:
                        # /home/buffer/antlr/JavaScript.g:236:37: ( LT )* callExpressionSuffix
                        pass 
                        # /home/buffer/antlr/JavaScript.g:236:39: ( LT )*
                        while True: #loop135
                            alt135 = 2
                            LA135_0 = self.input.LA(1)

                            if (LA135_0 == LT) :
                                alt135 = 1


                            if alt135 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT281=self.match(self.input, LT, self.FOLLOW_LT_in_callExpression1467)


                            else:
                                break #loop135
                        self._state.following.append(self.FOLLOW_callExpressionSuffix_in_callExpression1471)
                        callExpressionSuffix282 = self.callExpressionSuffix()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, callExpressionSuffix282.tree)


                    else:
                        break #loop136



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 49, callExpression_StartIndex, success)

            pass
        return retval

    # $ANTLR end "callExpression"

    class callExpressionSuffix_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.callExpressionSuffix_return, self).__init__()

            self.tree = None




    # $ANTLR start "callExpressionSuffix"
    # /home/buffer/antlr/JavaScript.g:239:1: callExpressionSuffix : ( arguments | indexSuffix | propertyReferenceSuffix );
    def callExpressionSuffix(self, ):

        retval = self.callExpressionSuffix_return()
        retval.start = self.input.LT(1)
        callExpressionSuffix_StartIndex = self.input.index()
        root_0 = None

        arguments283 = None

        indexSuffix284 = None

        propertyReferenceSuffix285 = None



        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 50):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:240:2: ( arguments | indexSuffix | propertyReferenceSuffix )
                alt137 = 3
                LA137 = self.input.LA(1)
                if LA137 == 32:
                    alt137 = 1
                elif LA137 == 59:
                    alt137 = 2
                elif LA137 == 61:
                    alt137 = 3
                else:
                    if self._state.backtracking > 0:
                        raise BacktrackingFailed

                    nvae = NoViableAltException("", 137, 0, self.input)

                    raise nvae

                if alt137 == 1:
                    # /home/buffer/antlr/JavaScript.g:240:4: arguments
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_arguments_in_callExpressionSuffix1485)
                    arguments283 = self.arguments()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, arguments283.tree)


                elif alt137 == 2:
                    # /home/buffer/antlr/JavaScript.g:241:4: indexSuffix
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_indexSuffix_in_callExpressionSuffix1490)
                    indexSuffix284 = self.indexSuffix()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, indexSuffix284.tree)


                elif alt137 == 3:
                    # /home/buffer/antlr/JavaScript.g:242:4: propertyReferenceSuffix
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_propertyReferenceSuffix_in_callExpressionSuffix1495)
                    propertyReferenceSuffix285 = self.propertyReferenceSuffix()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, propertyReferenceSuffix285.tree)


                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 50, callExpressionSuffix_StartIndex, success)

            pass
        return retval

    # $ANTLR end "callExpressionSuffix"

    class arguments_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.arguments_return, self).__init__()

            self.tree = None




    # $ANTLR start "arguments"
    # /home/buffer/antlr/JavaScript.g:245:1: arguments : '(' ( ( LT )* assignmentExpression ( ( LT )* ',' ( LT )* assignmentExpression )* )? ( LT )* ')' ;
    def arguments(self, ):

        retval = self.arguments_return()
        retval.start = self.input.LT(1)
        arguments_StartIndex = self.input.index()
        root_0 = None

        char_literal286 = None
        LT287 = None
        LT289 = None
        char_literal290 = None
        LT291 = None
        LT293 = None
        char_literal294 = None
        assignmentExpression288 = None

        assignmentExpression292 = None


        char_literal286_tree = None
        LT287_tree = None
        LT289_tree = None
        char_literal290_tree = None
        LT291_tree = None
        LT293_tree = None
        char_literal294_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 51):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:246:2: ( '(' ( ( LT )* assignmentExpression ( ( LT )* ',' ( LT )* assignmentExpression )* )? ( LT )* ')' )
                # /home/buffer/antlr/JavaScript.g:246:4: '(' ( ( LT )* assignmentExpression ( ( LT )* ',' ( LT )* assignmentExpression )* )? ( LT )* ')'
                pass 
                root_0 = self._adaptor.nil()

                char_literal286=self.match(self.input, 32, self.FOLLOW_32_in_arguments1506)
                if self._state.backtracking == 0:

                    char_literal286_tree = self._adaptor.createWithPayload(char_literal286)
                    self._adaptor.addChild(root_0, char_literal286_tree)

                # /home/buffer/antlr/JavaScript.g:246:8: ( ( LT )* assignmentExpression ( ( LT )* ',' ( LT )* assignmentExpression )* )?
                alt142 = 2
                alt142 = self.dfa142.predict(self.input)
                if alt142 == 1:
                    # /home/buffer/antlr/JavaScript.g:246:9: ( LT )* assignmentExpression ( ( LT )* ',' ( LT )* assignmentExpression )*
                    pass 
                    # /home/buffer/antlr/JavaScript.g:246:11: ( LT )*
                    while True: #loop138
                        alt138 = 2
                        LA138_0 = self.input.LA(1)

                        if (LA138_0 == LT) :
                            alt138 = 1


                        if alt138 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT287=self.match(self.input, LT, self.FOLLOW_LT_in_arguments1509)


                        else:
                            break #loop138
                    self._state.following.append(self.FOLLOW_assignmentExpression_in_arguments1513)
                    assignmentExpression288 = self.assignmentExpression()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, assignmentExpression288.tree)
                    # /home/buffer/antlr/JavaScript.g:246:35: ( ( LT )* ',' ( LT )* assignmentExpression )*
                    while True: #loop141
                        alt141 = 2
                        alt141 = self.dfa141.predict(self.input)
                        if alt141 == 1:
                            # /home/buffer/antlr/JavaScript.g:246:36: ( LT )* ',' ( LT )* assignmentExpression
                            pass 
                            # /home/buffer/antlr/JavaScript.g:246:38: ( LT )*
                            while True: #loop139
                                alt139 = 2
                                LA139_0 = self.input.LA(1)

                                if (LA139_0 == LT) :
                                    alt139 = 1


                                if alt139 == 1:
                                    # /home/buffer/antlr/JavaScript.g:0:0: LT
                                    pass 
                                    LT289=self.match(self.input, LT, self.FOLLOW_LT_in_arguments1516)


                                else:
                                    break #loop139
                            char_literal290=self.match(self.input, 33, self.FOLLOW_33_in_arguments1520)
                            if self._state.backtracking == 0:

                                char_literal290_tree = self._adaptor.createWithPayload(char_literal290)
                                self._adaptor.addChild(root_0, char_literal290_tree)

                            # /home/buffer/antlr/JavaScript.g:246:47: ( LT )*
                            while True: #loop140
                                alt140 = 2
                                LA140_0 = self.input.LA(1)

                                if (LA140_0 == LT) :
                                    alt140 = 1


                                if alt140 == 1:
                                    # /home/buffer/antlr/JavaScript.g:0:0: LT
                                    pass 
                                    LT291=self.match(self.input, LT, self.FOLLOW_LT_in_arguments1522)


                                else:
                                    break #loop140
                            self._state.following.append(self.FOLLOW_assignmentExpression_in_arguments1526)
                            assignmentExpression292 = self.assignmentExpression()

                            self._state.following.pop()
                            if self._state.backtracking == 0:
                                self._adaptor.addChild(root_0, assignmentExpression292.tree)


                        else:
                            break #loop141



                # /home/buffer/antlr/JavaScript.g:246:77: ( LT )*
                while True: #loop143
                    alt143 = 2
                    LA143_0 = self.input.LA(1)

                    if (LA143_0 == LT) :
                        alt143 = 1


                    if alt143 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT293=self.match(self.input, LT, self.FOLLOW_LT_in_arguments1532)


                    else:
                        break #loop143
                char_literal294=self.match(self.input, 34, self.FOLLOW_34_in_arguments1536)
                if self._state.backtracking == 0:

                    char_literal294_tree = self._adaptor.createWithPayload(char_literal294)
                    self._adaptor.addChild(root_0, char_literal294_tree)




                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 51, arguments_StartIndex, success)

            pass
        return retval

    # $ANTLR end "arguments"

    class indexSuffix_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.indexSuffix_return, self).__init__()

            self.tree = None




    # $ANTLR start "indexSuffix"
    # /home/buffer/antlr/JavaScript.g:249:1: indexSuffix : '[' ( LT )* expression ( LT )* ']' ;
    def indexSuffix(self, ):

        retval = self.indexSuffix_return()
        retval.start = self.input.LT(1)
        indexSuffix_StartIndex = self.input.index()
        root_0 = None

        char_literal295 = None
        LT296 = None
        LT298 = None
        char_literal299 = None
        expression297 = None


        char_literal295_tree = None
        LT296_tree = None
        LT298_tree = None
        char_literal299_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 52):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:250:2: ( '[' ( LT )* expression ( LT )* ']' )
                # /home/buffer/antlr/JavaScript.g:250:4: '[' ( LT )* expression ( LT )* ']'
                pass 
                root_0 = self._adaptor.nil()

                char_literal295=self.match(self.input, 59, self.FOLLOW_59_in_indexSuffix1548)
                if self._state.backtracking == 0:

                    char_literal295_tree = self._adaptor.createWithPayload(char_literal295)
                    self._adaptor.addChild(root_0, char_literal295_tree)

                # /home/buffer/antlr/JavaScript.g:250:10: ( LT )*
                while True: #loop144
                    alt144 = 2
                    LA144_0 = self.input.LA(1)

                    if (LA144_0 == LT) :
                        alt144 = 1


                    if alt144 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT296=self.match(self.input, LT, self.FOLLOW_LT_in_indexSuffix1550)


                    else:
                        break #loop144
                self._state.following.append(self.FOLLOW_expression_in_indexSuffix1554)
                expression297 = self.expression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, expression297.tree)
                # /home/buffer/antlr/JavaScript.g:250:26: ( LT )*
                while True: #loop145
                    alt145 = 2
                    LA145_0 = self.input.LA(1)

                    if (LA145_0 == LT) :
                        alt145 = 1


                    if alt145 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT298=self.match(self.input, LT, self.FOLLOW_LT_in_indexSuffix1556)


                    else:
                        break #loop145
                char_literal299=self.match(self.input, 60, self.FOLLOW_60_in_indexSuffix1560)
                if self._state.backtracking == 0:

                    char_literal299_tree = self._adaptor.createWithPayload(char_literal299)
                    self._adaptor.addChild(root_0, char_literal299_tree)




                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 52, indexSuffix_StartIndex, success)

            pass
        return retval

    # $ANTLR end "indexSuffix"

    class propertyReferenceSuffix_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.propertyReferenceSuffix_return, self).__init__()

            self.tree = None




    # $ANTLR start "propertyReferenceSuffix"
    # /home/buffer/antlr/JavaScript.g:253:1: propertyReferenceSuffix : '.' ( LT )* Identifier ;
    def propertyReferenceSuffix(self, ):

        retval = self.propertyReferenceSuffix_return()
        retval.start = self.input.LT(1)
        propertyReferenceSuffix_StartIndex = self.input.index()
        root_0 = None

        char_literal300 = None
        LT301 = None
        Identifier302 = None

        char_literal300_tree = None
        LT301_tree = None
        Identifier302_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 53):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:254:2: ( '.' ( LT )* Identifier )
                # /home/buffer/antlr/JavaScript.g:254:4: '.' ( LT )* Identifier
                pass 
                root_0 = self._adaptor.nil()

                char_literal300=self.match(self.input, 61, self.FOLLOW_61_in_propertyReferenceSuffix1573)
                if self._state.backtracking == 0:

                    char_literal300_tree = self._adaptor.createWithPayload(char_literal300)
                    self._adaptor.addChild(root_0, char_literal300_tree)

                # /home/buffer/antlr/JavaScript.g:254:10: ( LT )*
                while True: #loop146
                    alt146 = 2
                    LA146_0 = self.input.LA(1)

                    if (LA146_0 == LT) :
                        alt146 = 1


                    if alt146 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT301=self.match(self.input, LT, self.FOLLOW_LT_in_propertyReferenceSuffix1575)


                    else:
                        break #loop146
                Identifier302=self.match(self.input, Identifier, self.FOLLOW_Identifier_in_propertyReferenceSuffix1579)
                if self._state.backtracking == 0:

                    Identifier302_tree = self._adaptor.createWithPayload(Identifier302)
                    self._adaptor.addChild(root_0, Identifier302_tree)




                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 53, propertyReferenceSuffix_StartIndex, success)

            pass
        return retval

    # $ANTLR end "propertyReferenceSuffix"

    class assignmentOperator_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.assignmentOperator_return, self).__init__()

            self.tree = None




    # $ANTLR start "assignmentOperator"
    # /home/buffer/antlr/JavaScript.g:257:1: assignmentOperator : ( '=' | '*=' | '/=' | '%=' | '+=' | '-=' | '<<=' | '>>=' | '>>>=' | '&=' | '^=' | '|=' );
    def assignmentOperator(self, ):

        retval = self.assignmentOperator_return()
        retval.start = self.input.LT(1)
        assignmentOperator_StartIndex = self.input.index()
        root_0 = None

        set303 = None

        set303_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 54):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:258:2: ( '=' | '*=' | '/=' | '%=' | '+=' | '-=' | '<<=' | '>>=' | '>>>=' | '&=' | '^=' | '|=' )
                # /home/buffer/antlr/JavaScript.g:
                pass 
                root_0 = self._adaptor.nil()

                set303 = self.input.LT(1)
                if self.input.LA(1) == 39 or (62 <= self.input.LA(1) <= 72):
                    self.input.consume()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, self._adaptor.createWithPayload(set303))
                    self._state.errorRecovery = False

                else:
                    if self._state.backtracking > 0:
                        raise BacktrackingFailed

                    mse = MismatchedSetException(None, self.input)
                    raise mse





                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 54, assignmentOperator_StartIndex, success)

            pass
        return retval

    # $ANTLR end "assignmentOperator"

    class conditionalExpression_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.conditionalExpression_return, self).__init__()

            self.tree = None




    # $ANTLR start "conditionalExpression"
    # /home/buffer/antlr/JavaScript.g:261:1: conditionalExpression : logicalORExpression ( ( LT )* '?' ( LT )* assignmentExpression ( LT )* ':' ( LT )* assignmentExpression )? ;
    def conditionalExpression(self, ):

        retval = self.conditionalExpression_return()
        retval.start = self.input.LT(1)
        conditionalExpression_StartIndex = self.input.index()
        root_0 = None

        LT305 = None
        char_literal306 = None
        LT307 = None
        LT309 = None
        char_literal310 = None
        LT311 = None
        logicalORExpression304 = None

        assignmentExpression308 = None

        assignmentExpression312 = None


        LT305_tree = None
        char_literal306_tree = None
        LT307_tree = None
        LT309_tree = None
        char_literal310_tree = None
        LT311_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 55):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:262:2: ( logicalORExpression ( ( LT )* '?' ( LT )* assignmentExpression ( LT )* ':' ( LT )* assignmentExpression )? )
                # /home/buffer/antlr/JavaScript.g:262:4: logicalORExpression ( ( LT )* '?' ( LT )* assignmentExpression ( LT )* ':' ( LT )* assignmentExpression )?
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_logicalORExpression_in_conditionalExpression1646)
                logicalORExpression304 = self.logicalORExpression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, logicalORExpression304.tree)
                # /home/buffer/antlr/JavaScript.g:262:24: ( ( LT )* '?' ( LT )* assignmentExpression ( LT )* ':' ( LT )* assignmentExpression )?
                alt151 = 2
                alt151 = self.dfa151.predict(self.input)
                if alt151 == 1:
                    # /home/buffer/antlr/JavaScript.g:262:25: ( LT )* '?' ( LT )* assignmentExpression ( LT )* ':' ( LT )* assignmentExpression
                    pass 
                    # /home/buffer/antlr/JavaScript.g:262:27: ( LT )*
                    while True: #loop147
                        alt147 = 2
                        LA147_0 = self.input.LA(1)

                        if (LA147_0 == LT) :
                            alt147 = 1


                        if alt147 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT305=self.match(self.input, LT, self.FOLLOW_LT_in_conditionalExpression1649)


                        else:
                            break #loop147
                    char_literal306=self.match(self.input, 73, self.FOLLOW_73_in_conditionalExpression1653)
                    if self._state.backtracking == 0:

                        char_literal306_tree = self._adaptor.createWithPayload(char_literal306)
                        self._adaptor.addChild(root_0, char_literal306_tree)

                    # /home/buffer/antlr/JavaScript.g:262:36: ( LT )*
                    while True: #loop148
                        alt148 = 2
                        LA148_0 = self.input.LA(1)

                        if (LA148_0 == LT) :
                            alt148 = 1


                        if alt148 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT307=self.match(self.input, LT, self.FOLLOW_LT_in_conditionalExpression1655)


                        else:
                            break #loop148
                    self._state.following.append(self.FOLLOW_assignmentExpression_in_conditionalExpression1659)
                    assignmentExpression308 = self.assignmentExpression()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, assignmentExpression308.tree)
                    # /home/buffer/antlr/JavaScript.g:262:62: ( LT )*
                    while True: #loop149
                        alt149 = 2
                        LA149_0 = self.input.LA(1)

                        if (LA149_0 == LT) :
                            alt149 = 1


                        if alt149 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT309=self.match(self.input, LT, self.FOLLOW_LT_in_conditionalExpression1661)


                        else:
                            break #loop149
                    char_literal310=self.match(self.input, 50, self.FOLLOW_50_in_conditionalExpression1665)
                    if self._state.backtracking == 0:

                        char_literal310_tree = self._adaptor.createWithPayload(char_literal310)
                        self._adaptor.addChild(root_0, char_literal310_tree)

                    # /home/buffer/antlr/JavaScript.g:262:71: ( LT )*
                    while True: #loop150
                        alt150 = 2
                        LA150_0 = self.input.LA(1)

                        if (LA150_0 == LT) :
                            alt150 = 1


                        if alt150 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT311=self.match(self.input, LT, self.FOLLOW_LT_in_conditionalExpression1667)


                        else:
                            break #loop150
                    self._state.following.append(self.FOLLOW_assignmentExpression_in_conditionalExpression1671)
                    assignmentExpression312 = self.assignmentExpression()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, assignmentExpression312.tree)






                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 55, conditionalExpression_StartIndex, success)

            pass
        return retval

    # $ANTLR end "conditionalExpression"

    class conditionalExpressionNoIn_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.conditionalExpressionNoIn_return, self).__init__()

            self.tree = None




    # $ANTLR start "conditionalExpressionNoIn"
    # /home/buffer/antlr/JavaScript.g:265:1: conditionalExpressionNoIn : logicalORExpressionNoIn ( ( LT )* '?' ( LT )* assignmentExpressionNoIn ( LT )* ':' ( LT )* assignmentExpressionNoIn )? ;
    def conditionalExpressionNoIn(self, ):

        retval = self.conditionalExpressionNoIn_return()
        retval.start = self.input.LT(1)
        conditionalExpressionNoIn_StartIndex = self.input.index()
        root_0 = None

        LT314 = None
        char_literal315 = None
        LT316 = None
        LT318 = None
        char_literal319 = None
        LT320 = None
        logicalORExpressionNoIn313 = None

        assignmentExpressionNoIn317 = None

        assignmentExpressionNoIn321 = None


        LT314_tree = None
        char_literal315_tree = None
        LT316_tree = None
        LT318_tree = None
        char_literal319_tree = None
        LT320_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 56):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:266:2: ( logicalORExpressionNoIn ( ( LT )* '?' ( LT )* assignmentExpressionNoIn ( LT )* ':' ( LT )* assignmentExpressionNoIn )? )
                # /home/buffer/antlr/JavaScript.g:266:4: logicalORExpressionNoIn ( ( LT )* '?' ( LT )* assignmentExpressionNoIn ( LT )* ':' ( LT )* assignmentExpressionNoIn )?
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_logicalORExpressionNoIn_in_conditionalExpressionNoIn1684)
                logicalORExpressionNoIn313 = self.logicalORExpressionNoIn()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, logicalORExpressionNoIn313.tree)
                # /home/buffer/antlr/JavaScript.g:266:28: ( ( LT )* '?' ( LT )* assignmentExpressionNoIn ( LT )* ':' ( LT )* assignmentExpressionNoIn )?
                alt156 = 2
                alt156 = self.dfa156.predict(self.input)
                if alt156 == 1:
                    # /home/buffer/antlr/JavaScript.g:266:29: ( LT )* '?' ( LT )* assignmentExpressionNoIn ( LT )* ':' ( LT )* assignmentExpressionNoIn
                    pass 
                    # /home/buffer/antlr/JavaScript.g:266:31: ( LT )*
                    while True: #loop152
                        alt152 = 2
                        LA152_0 = self.input.LA(1)

                        if (LA152_0 == LT) :
                            alt152 = 1


                        if alt152 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT314=self.match(self.input, LT, self.FOLLOW_LT_in_conditionalExpressionNoIn1687)


                        else:
                            break #loop152
                    char_literal315=self.match(self.input, 73, self.FOLLOW_73_in_conditionalExpressionNoIn1691)
                    if self._state.backtracking == 0:

                        char_literal315_tree = self._adaptor.createWithPayload(char_literal315)
                        self._adaptor.addChild(root_0, char_literal315_tree)

                    # /home/buffer/antlr/JavaScript.g:266:40: ( LT )*
                    while True: #loop153
                        alt153 = 2
                        LA153_0 = self.input.LA(1)

                        if (LA153_0 == LT) :
                            alt153 = 1


                        if alt153 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT316=self.match(self.input, LT, self.FOLLOW_LT_in_conditionalExpressionNoIn1693)


                        else:
                            break #loop153
                    self._state.following.append(self.FOLLOW_assignmentExpressionNoIn_in_conditionalExpressionNoIn1697)
                    assignmentExpressionNoIn317 = self.assignmentExpressionNoIn()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, assignmentExpressionNoIn317.tree)
                    # /home/buffer/antlr/JavaScript.g:266:70: ( LT )*
                    while True: #loop154
                        alt154 = 2
                        LA154_0 = self.input.LA(1)

                        if (LA154_0 == LT) :
                            alt154 = 1


                        if alt154 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT318=self.match(self.input, LT, self.FOLLOW_LT_in_conditionalExpressionNoIn1699)


                        else:
                            break #loop154
                    char_literal319=self.match(self.input, 50, self.FOLLOW_50_in_conditionalExpressionNoIn1703)
                    if self._state.backtracking == 0:

                        char_literal319_tree = self._adaptor.createWithPayload(char_literal319)
                        self._adaptor.addChild(root_0, char_literal319_tree)

                    # /home/buffer/antlr/JavaScript.g:266:79: ( LT )*
                    while True: #loop155
                        alt155 = 2
                        LA155_0 = self.input.LA(1)

                        if (LA155_0 == LT) :
                            alt155 = 1


                        if alt155 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT320=self.match(self.input, LT, self.FOLLOW_LT_in_conditionalExpressionNoIn1705)


                        else:
                            break #loop155
                    self._state.following.append(self.FOLLOW_assignmentExpressionNoIn_in_conditionalExpressionNoIn1709)
                    assignmentExpressionNoIn321 = self.assignmentExpressionNoIn()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, assignmentExpressionNoIn321.tree)






                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 56, conditionalExpressionNoIn_StartIndex, success)

            pass
        return retval

    # $ANTLR end "conditionalExpressionNoIn"

    class logicalORExpression_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.logicalORExpression_return, self).__init__()

            self.tree = None




    # $ANTLR start "logicalORExpression"
    # /home/buffer/antlr/JavaScript.g:269:1: logicalORExpression : logicalANDExpression ( ( LT )* '||' ( LT )* logicalANDExpression )* ;
    def logicalORExpression(self, ):

        retval = self.logicalORExpression_return()
        retval.start = self.input.LT(1)
        logicalORExpression_StartIndex = self.input.index()
        root_0 = None

        LT323 = None
        string_literal324 = None
        LT325 = None
        logicalANDExpression322 = None

        logicalANDExpression326 = None


        LT323_tree = None
        string_literal324_tree = None
        LT325_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 57):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:270:2: ( logicalANDExpression ( ( LT )* '||' ( LT )* logicalANDExpression )* )
                # /home/buffer/antlr/JavaScript.g:270:4: logicalANDExpression ( ( LT )* '||' ( LT )* logicalANDExpression )*
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_logicalANDExpression_in_logicalORExpression1722)
                logicalANDExpression322 = self.logicalANDExpression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, logicalANDExpression322.tree)
                # /home/buffer/antlr/JavaScript.g:270:25: ( ( LT )* '||' ( LT )* logicalANDExpression )*
                while True: #loop159
                    alt159 = 2
                    alt159 = self.dfa159.predict(self.input)
                    if alt159 == 1:
                        # /home/buffer/antlr/JavaScript.g:270:26: ( LT )* '||' ( LT )* logicalANDExpression
                        pass 
                        # /home/buffer/antlr/JavaScript.g:270:28: ( LT )*
                        while True: #loop157
                            alt157 = 2
                            LA157_0 = self.input.LA(1)

                            if (LA157_0 == LT) :
                                alt157 = 1


                            if alt157 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT323=self.match(self.input, LT, self.FOLLOW_LT_in_logicalORExpression1725)


                            else:
                                break #loop157
                        string_literal324=self.match(self.input, 74, self.FOLLOW_74_in_logicalORExpression1729)
                        if self._state.backtracking == 0:

                            string_literal324_tree = self._adaptor.createWithPayload(string_literal324)
                            self._adaptor.addChild(root_0, string_literal324_tree)

                        # /home/buffer/antlr/JavaScript.g:270:38: ( LT )*
                        while True: #loop158
                            alt158 = 2
                            LA158_0 = self.input.LA(1)

                            if (LA158_0 == LT) :
                                alt158 = 1


                            if alt158 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT325=self.match(self.input, LT, self.FOLLOW_LT_in_logicalORExpression1731)


                            else:
                                break #loop158
                        self._state.following.append(self.FOLLOW_logicalANDExpression_in_logicalORExpression1735)
                        logicalANDExpression326 = self.logicalANDExpression()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, logicalANDExpression326.tree)


                    else:
                        break #loop159



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 57, logicalORExpression_StartIndex, success)

            pass
        return retval

    # $ANTLR end "logicalORExpression"

    class logicalORExpressionNoIn_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.logicalORExpressionNoIn_return, self).__init__()

            self.tree = None




    # $ANTLR start "logicalORExpressionNoIn"
    # /home/buffer/antlr/JavaScript.g:273:1: logicalORExpressionNoIn : logicalANDExpressionNoIn ( ( LT )* '||' ( LT )* logicalANDExpressionNoIn )* ;
    def logicalORExpressionNoIn(self, ):

        retval = self.logicalORExpressionNoIn_return()
        retval.start = self.input.LT(1)
        logicalORExpressionNoIn_StartIndex = self.input.index()
        root_0 = None

        LT328 = None
        string_literal329 = None
        LT330 = None
        logicalANDExpressionNoIn327 = None

        logicalANDExpressionNoIn331 = None


        LT328_tree = None
        string_literal329_tree = None
        LT330_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 58):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:274:2: ( logicalANDExpressionNoIn ( ( LT )* '||' ( LT )* logicalANDExpressionNoIn )* )
                # /home/buffer/antlr/JavaScript.g:274:4: logicalANDExpressionNoIn ( ( LT )* '||' ( LT )* logicalANDExpressionNoIn )*
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_logicalANDExpressionNoIn_in_logicalORExpressionNoIn1749)
                logicalANDExpressionNoIn327 = self.logicalANDExpressionNoIn()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, logicalANDExpressionNoIn327.tree)
                # /home/buffer/antlr/JavaScript.g:274:29: ( ( LT )* '||' ( LT )* logicalANDExpressionNoIn )*
                while True: #loop162
                    alt162 = 2
                    alt162 = self.dfa162.predict(self.input)
                    if alt162 == 1:
                        # /home/buffer/antlr/JavaScript.g:274:30: ( LT )* '||' ( LT )* logicalANDExpressionNoIn
                        pass 
                        # /home/buffer/antlr/JavaScript.g:274:32: ( LT )*
                        while True: #loop160
                            alt160 = 2
                            LA160_0 = self.input.LA(1)

                            if (LA160_0 == LT) :
                                alt160 = 1


                            if alt160 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT328=self.match(self.input, LT, self.FOLLOW_LT_in_logicalORExpressionNoIn1752)


                            else:
                                break #loop160
                        string_literal329=self.match(self.input, 74, self.FOLLOW_74_in_logicalORExpressionNoIn1756)
                        if self._state.backtracking == 0:

                            string_literal329_tree = self._adaptor.createWithPayload(string_literal329)
                            self._adaptor.addChild(root_0, string_literal329_tree)

                        # /home/buffer/antlr/JavaScript.g:274:42: ( LT )*
                        while True: #loop161
                            alt161 = 2
                            LA161_0 = self.input.LA(1)

                            if (LA161_0 == LT) :
                                alt161 = 1


                            if alt161 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT330=self.match(self.input, LT, self.FOLLOW_LT_in_logicalORExpressionNoIn1758)


                            else:
                                break #loop161
                        self._state.following.append(self.FOLLOW_logicalANDExpressionNoIn_in_logicalORExpressionNoIn1762)
                        logicalANDExpressionNoIn331 = self.logicalANDExpressionNoIn()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, logicalANDExpressionNoIn331.tree)


                    else:
                        break #loop162



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 58, logicalORExpressionNoIn_StartIndex, success)

            pass
        return retval

    # $ANTLR end "logicalORExpressionNoIn"

    class logicalANDExpression_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.logicalANDExpression_return, self).__init__()

            self.tree = None




    # $ANTLR start "logicalANDExpression"
    # /home/buffer/antlr/JavaScript.g:277:1: logicalANDExpression : bitwiseORExpression ( ( LT )* '&&' ( LT )* bitwiseORExpression )* ;
    def logicalANDExpression(self, ):

        retval = self.logicalANDExpression_return()
        retval.start = self.input.LT(1)
        logicalANDExpression_StartIndex = self.input.index()
        root_0 = None

        LT333 = None
        string_literal334 = None
        LT335 = None
        bitwiseORExpression332 = None

        bitwiseORExpression336 = None


        LT333_tree = None
        string_literal334_tree = None
        LT335_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 59):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:278:2: ( bitwiseORExpression ( ( LT )* '&&' ( LT )* bitwiseORExpression )* )
                # /home/buffer/antlr/JavaScript.g:278:4: bitwiseORExpression ( ( LT )* '&&' ( LT )* bitwiseORExpression )*
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_bitwiseORExpression_in_logicalANDExpression1776)
                bitwiseORExpression332 = self.bitwiseORExpression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, bitwiseORExpression332.tree)
                # /home/buffer/antlr/JavaScript.g:278:24: ( ( LT )* '&&' ( LT )* bitwiseORExpression )*
                while True: #loop165
                    alt165 = 2
                    alt165 = self.dfa165.predict(self.input)
                    if alt165 == 1:
                        # /home/buffer/antlr/JavaScript.g:278:25: ( LT )* '&&' ( LT )* bitwiseORExpression
                        pass 
                        # /home/buffer/antlr/JavaScript.g:278:27: ( LT )*
                        while True: #loop163
                            alt163 = 2
                            LA163_0 = self.input.LA(1)

                            if (LA163_0 == LT) :
                                alt163 = 1


                            if alt163 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT333=self.match(self.input, LT, self.FOLLOW_LT_in_logicalANDExpression1779)


                            else:
                                break #loop163
                        string_literal334=self.match(self.input, 75, self.FOLLOW_75_in_logicalANDExpression1783)
                        if self._state.backtracking == 0:

                            string_literal334_tree = self._adaptor.createWithPayload(string_literal334)
                            self._adaptor.addChild(root_0, string_literal334_tree)

                        # /home/buffer/antlr/JavaScript.g:278:37: ( LT )*
                        while True: #loop164
                            alt164 = 2
                            LA164_0 = self.input.LA(1)

                            if (LA164_0 == LT) :
                                alt164 = 1


                            if alt164 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT335=self.match(self.input, LT, self.FOLLOW_LT_in_logicalANDExpression1785)


                            else:
                                break #loop164
                        self._state.following.append(self.FOLLOW_bitwiseORExpression_in_logicalANDExpression1789)
                        bitwiseORExpression336 = self.bitwiseORExpression()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, bitwiseORExpression336.tree)


                    else:
                        break #loop165



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 59, logicalANDExpression_StartIndex, success)

            pass
        return retval

    # $ANTLR end "logicalANDExpression"

    class logicalANDExpressionNoIn_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.logicalANDExpressionNoIn_return, self).__init__()

            self.tree = None




    # $ANTLR start "logicalANDExpressionNoIn"
    # /home/buffer/antlr/JavaScript.g:281:1: logicalANDExpressionNoIn : bitwiseORExpressionNoIn ( ( LT )* '&&' ( LT )* bitwiseORExpressionNoIn )* ;
    def logicalANDExpressionNoIn(self, ):

        retval = self.logicalANDExpressionNoIn_return()
        retval.start = self.input.LT(1)
        logicalANDExpressionNoIn_StartIndex = self.input.index()
        root_0 = None

        LT338 = None
        string_literal339 = None
        LT340 = None
        bitwiseORExpressionNoIn337 = None

        bitwiseORExpressionNoIn341 = None


        LT338_tree = None
        string_literal339_tree = None
        LT340_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 60):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:282:2: ( bitwiseORExpressionNoIn ( ( LT )* '&&' ( LT )* bitwiseORExpressionNoIn )* )
                # /home/buffer/antlr/JavaScript.g:282:4: bitwiseORExpressionNoIn ( ( LT )* '&&' ( LT )* bitwiseORExpressionNoIn )*
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_bitwiseORExpressionNoIn_in_logicalANDExpressionNoIn1803)
                bitwiseORExpressionNoIn337 = self.bitwiseORExpressionNoIn()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, bitwiseORExpressionNoIn337.tree)
                # /home/buffer/antlr/JavaScript.g:282:28: ( ( LT )* '&&' ( LT )* bitwiseORExpressionNoIn )*
                while True: #loop168
                    alt168 = 2
                    alt168 = self.dfa168.predict(self.input)
                    if alt168 == 1:
                        # /home/buffer/antlr/JavaScript.g:282:29: ( LT )* '&&' ( LT )* bitwiseORExpressionNoIn
                        pass 
                        # /home/buffer/antlr/JavaScript.g:282:31: ( LT )*
                        while True: #loop166
                            alt166 = 2
                            LA166_0 = self.input.LA(1)

                            if (LA166_0 == LT) :
                                alt166 = 1


                            if alt166 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT338=self.match(self.input, LT, self.FOLLOW_LT_in_logicalANDExpressionNoIn1806)


                            else:
                                break #loop166
                        string_literal339=self.match(self.input, 75, self.FOLLOW_75_in_logicalANDExpressionNoIn1810)
                        if self._state.backtracking == 0:

                            string_literal339_tree = self._adaptor.createWithPayload(string_literal339)
                            self._adaptor.addChild(root_0, string_literal339_tree)

                        # /home/buffer/antlr/JavaScript.g:282:41: ( LT )*
                        while True: #loop167
                            alt167 = 2
                            LA167_0 = self.input.LA(1)

                            if (LA167_0 == LT) :
                                alt167 = 1


                            if alt167 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT340=self.match(self.input, LT, self.FOLLOW_LT_in_logicalANDExpressionNoIn1812)


                            else:
                                break #loop167
                        self._state.following.append(self.FOLLOW_bitwiseORExpressionNoIn_in_logicalANDExpressionNoIn1816)
                        bitwiseORExpressionNoIn341 = self.bitwiseORExpressionNoIn()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, bitwiseORExpressionNoIn341.tree)


                    else:
                        break #loop168



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 60, logicalANDExpressionNoIn_StartIndex, success)

            pass
        return retval

    # $ANTLR end "logicalANDExpressionNoIn"

    class bitwiseORExpression_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.bitwiseORExpression_return, self).__init__()

            self.tree = None




    # $ANTLR start "bitwiseORExpression"
    # /home/buffer/antlr/JavaScript.g:285:1: bitwiseORExpression : bitwiseXORExpression ( ( LT )* '|' ( LT )* bitwiseXORExpression )* ;
    def bitwiseORExpression(self, ):

        retval = self.bitwiseORExpression_return()
        retval.start = self.input.LT(1)
        bitwiseORExpression_StartIndex = self.input.index()
        root_0 = None

        LT343 = None
        char_literal344 = None
        LT345 = None
        bitwiseXORExpression342 = None

        bitwiseXORExpression346 = None


        LT343_tree = None
        char_literal344_tree = None
        LT345_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 61):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:286:2: ( bitwiseXORExpression ( ( LT )* '|' ( LT )* bitwiseXORExpression )* )
                # /home/buffer/antlr/JavaScript.g:286:4: bitwiseXORExpression ( ( LT )* '|' ( LT )* bitwiseXORExpression )*
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_bitwiseXORExpression_in_bitwiseORExpression1830)
                bitwiseXORExpression342 = self.bitwiseXORExpression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, bitwiseXORExpression342.tree)
                # /home/buffer/antlr/JavaScript.g:286:25: ( ( LT )* '|' ( LT )* bitwiseXORExpression )*
                while True: #loop171
                    alt171 = 2
                    alt171 = self.dfa171.predict(self.input)
                    if alt171 == 1:
                        # /home/buffer/antlr/JavaScript.g:286:26: ( LT )* '|' ( LT )* bitwiseXORExpression
                        pass 
                        # /home/buffer/antlr/JavaScript.g:286:28: ( LT )*
                        while True: #loop169
                            alt169 = 2
                            LA169_0 = self.input.LA(1)

                            if (LA169_0 == LT) :
                                alt169 = 1


                            if alt169 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT343=self.match(self.input, LT, self.FOLLOW_LT_in_bitwiseORExpression1833)


                            else:
                                break #loop169
                        char_literal344=self.match(self.input, 76, self.FOLLOW_76_in_bitwiseORExpression1837)
                        if self._state.backtracking == 0:

                            char_literal344_tree = self._adaptor.createWithPayload(char_literal344)
                            self._adaptor.addChild(root_0, char_literal344_tree)

                        # /home/buffer/antlr/JavaScript.g:286:37: ( LT )*
                        while True: #loop170
                            alt170 = 2
                            LA170_0 = self.input.LA(1)

                            if (LA170_0 == LT) :
                                alt170 = 1


                            if alt170 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT345=self.match(self.input, LT, self.FOLLOW_LT_in_bitwiseORExpression1839)


                            else:
                                break #loop170
                        self._state.following.append(self.FOLLOW_bitwiseXORExpression_in_bitwiseORExpression1843)
                        bitwiseXORExpression346 = self.bitwiseXORExpression()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, bitwiseXORExpression346.tree)


                    else:
                        break #loop171



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 61, bitwiseORExpression_StartIndex, success)

            pass
        return retval

    # $ANTLR end "bitwiseORExpression"

    class bitwiseORExpressionNoIn_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.bitwiseORExpressionNoIn_return, self).__init__()

            self.tree = None




    # $ANTLR start "bitwiseORExpressionNoIn"
    # /home/buffer/antlr/JavaScript.g:289:1: bitwiseORExpressionNoIn : bitwiseXORExpressionNoIn ( ( LT )* '|' ( LT )* bitwiseXORExpressionNoIn )* ;
    def bitwiseORExpressionNoIn(self, ):

        retval = self.bitwiseORExpressionNoIn_return()
        retval.start = self.input.LT(1)
        bitwiseORExpressionNoIn_StartIndex = self.input.index()
        root_0 = None

        LT348 = None
        char_literal349 = None
        LT350 = None
        bitwiseXORExpressionNoIn347 = None

        bitwiseXORExpressionNoIn351 = None


        LT348_tree = None
        char_literal349_tree = None
        LT350_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 62):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:290:2: ( bitwiseXORExpressionNoIn ( ( LT )* '|' ( LT )* bitwiseXORExpressionNoIn )* )
                # /home/buffer/antlr/JavaScript.g:290:4: bitwiseXORExpressionNoIn ( ( LT )* '|' ( LT )* bitwiseXORExpressionNoIn )*
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_bitwiseXORExpressionNoIn_in_bitwiseORExpressionNoIn1857)
                bitwiseXORExpressionNoIn347 = self.bitwiseXORExpressionNoIn()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, bitwiseXORExpressionNoIn347.tree)
                # /home/buffer/antlr/JavaScript.g:290:29: ( ( LT )* '|' ( LT )* bitwiseXORExpressionNoIn )*
                while True: #loop174
                    alt174 = 2
                    alt174 = self.dfa174.predict(self.input)
                    if alt174 == 1:
                        # /home/buffer/antlr/JavaScript.g:290:30: ( LT )* '|' ( LT )* bitwiseXORExpressionNoIn
                        pass 
                        # /home/buffer/antlr/JavaScript.g:290:32: ( LT )*
                        while True: #loop172
                            alt172 = 2
                            LA172_0 = self.input.LA(1)

                            if (LA172_0 == LT) :
                                alt172 = 1


                            if alt172 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT348=self.match(self.input, LT, self.FOLLOW_LT_in_bitwiseORExpressionNoIn1860)


                            else:
                                break #loop172
                        char_literal349=self.match(self.input, 76, self.FOLLOW_76_in_bitwiseORExpressionNoIn1864)
                        if self._state.backtracking == 0:

                            char_literal349_tree = self._adaptor.createWithPayload(char_literal349)
                            self._adaptor.addChild(root_0, char_literal349_tree)

                        # /home/buffer/antlr/JavaScript.g:290:41: ( LT )*
                        while True: #loop173
                            alt173 = 2
                            LA173_0 = self.input.LA(1)

                            if (LA173_0 == LT) :
                                alt173 = 1


                            if alt173 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT350=self.match(self.input, LT, self.FOLLOW_LT_in_bitwiseORExpressionNoIn1866)


                            else:
                                break #loop173
                        self._state.following.append(self.FOLLOW_bitwiseXORExpressionNoIn_in_bitwiseORExpressionNoIn1870)
                        bitwiseXORExpressionNoIn351 = self.bitwiseXORExpressionNoIn()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, bitwiseXORExpressionNoIn351.tree)


                    else:
                        break #loop174



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 62, bitwiseORExpressionNoIn_StartIndex, success)

            pass
        return retval

    # $ANTLR end "bitwiseORExpressionNoIn"

    class bitwiseXORExpression_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.bitwiseXORExpression_return, self).__init__()

            self.tree = None




    # $ANTLR start "bitwiseXORExpression"
    # /home/buffer/antlr/JavaScript.g:293:1: bitwiseXORExpression : bitwiseANDExpression ( ( LT )* '^' ( LT )* bitwiseANDExpression )* ;
    def bitwiseXORExpression(self, ):

        retval = self.bitwiseXORExpression_return()
        retval.start = self.input.LT(1)
        bitwiseXORExpression_StartIndex = self.input.index()
        root_0 = None

        LT353 = None
        char_literal354 = None
        LT355 = None
        bitwiseANDExpression352 = None

        bitwiseANDExpression356 = None


        LT353_tree = None
        char_literal354_tree = None
        LT355_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 63):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:294:2: ( bitwiseANDExpression ( ( LT )* '^' ( LT )* bitwiseANDExpression )* )
                # /home/buffer/antlr/JavaScript.g:294:4: bitwiseANDExpression ( ( LT )* '^' ( LT )* bitwiseANDExpression )*
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_bitwiseANDExpression_in_bitwiseXORExpression1884)
                bitwiseANDExpression352 = self.bitwiseANDExpression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, bitwiseANDExpression352.tree)
                # /home/buffer/antlr/JavaScript.g:294:25: ( ( LT )* '^' ( LT )* bitwiseANDExpression )*
                while True: #loop177
                    alt177 = 2
                    alt177 = self.dfa177.predict(self.input)
                    if alt177 == 1:
                        # /home/buffer/antlr/JavaScript.g:294:26: ( LT )* '^' ( LT )* bitwiseANDExpression
                        pass 
                        # /home/buffer/antlr/JavaScript.g:294:28: ( LT )*
                        while True: #loop175
                            alt175 = 2
                            LA175_0 = self.input.LA(1)

                            if (LA175_0 == LT) :
                                alt175 = 1


                            if alt175 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT353=self.match(self.input, LT, self.FOLLOW_LT_in_bitwiseXORExpression1887)


                            else:
                                break #loop175
                        char_literal354=self.match(self.input, 77, self.FOLLOW_77_in_bitwiseXORExpression1891)
                        if self._state.backtracking == 0:

                            char_literal354_tree = self._adaptor.createWithPayload(char_literal354)
                            self._adaptor.addChild(root_0, char_literal354_tree)

                        # /home/buffer/antlr/JavaScript.g:294:37: ( LT )*
                        while True: #loop176
                            alt176 = 2
                            LA176_0 = self.input.LA(1)

                            if (LA176_0 == LT) :
                                alt176 = 1


                            if alt176 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT355=self.match(self.input, LT, self.FOLLOW_LT_in_bitwiseXORExpression1893)


                            else:
                                break #loop176
                        self._state.following.append(self.FOLLOW_bitwiseANDExpression_in_bitwiseXORExpression1897)
                        bitwiseANDExpression356 = self.bitwiseANDExpression()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, bitwiseANDExpression356.tree)


                    else:
                        break #loop177



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 63, bitwiseXORExpression_StartIndex, success)

            pass
        return retval

    # $ANTLR end "bitwiseXORExpression"

    class bitwiseXORExpressionNoIn_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.bitwiseXORExpressionNoIn_return, self).__init__()

            self.tree = None




    # $ANTLR start "bitwiseXORExpressionNoIn"
    # /home/buffer/antlr/JavaScript.g:297:1: bitwiseXORExpressionNoIn : bitwiseANDExpressionNoIn ( ( LT )* '^' ( LT )* bitwiseANDExpressionNoIn )* ;
    def bitwiseXORExpressionNoIn(self, ):

        retval = self.bitwiseXORExpressionNoIn_return()
        retval.start = self.input.LT(1)
        bitwiseXORExpressionNoIn_StartIndex = self.input.index()
        root_0 = None

        LT358 = None
        char_literal359 = None
        LT360 = None
        bitwiseANDExpressionNoIn357 = None

        bitwiseANDExpressionNoIn361 = None


        LT358_tree = None
        char_literal359_tree = None
        LT360_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 64):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:298:2: ( bitwiseANDExpressionNoIn ( ( LT )* '^' ( LT )* bitwiseANDExpressionNoIn )* )
                # /home/buffer/antlr/JavaScript.g:298:4: bitwiseANDExpressionNoIn ( ( LT )* '^' ( LT )* bitwiseANDExpressionNoIn )*
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_bitwiseANDExpressionNoIn_in_bitwiseXORExpressionNoIn1911)
                bitwiseANDExpressionNoIn357 = self.bitwiseANDExpressionNoIn()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, bitwiseANDExpressionNoIn357.tree)
                # /home/buffer/antlr/JavaScript.g:298:29: ( ( LT )* '^' ( LT )* bitwiseANDExpressionNoIn )*
                while True: #loop180
                    alt180 = 2
                    alt180 = self.dfa180.predict(self.input)
                    if alt180 == 1:
                        # /home/buffer/antlr/JavaScript.g:298:30: ( LT )* '^' ( LT )* bitwiseANDExpressionNoIn
                        pass 
                        # /home/buffer/antlr/JavaScript.g:298:32: ( LT )*
                        while True: #loop178
                            alt178 = 2
                            LA178_0 = self.input.LA(1)

                            if (LA178_0 == LT) :
                                alt178 = 1


                            if alt178 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT358=self.match(self.input, LT, self.FOLLOW_LT_in_bitwiseXORExpressionNoIn1914)


                            else:
                                break #loop178
                        char_literal359=self.match(self.input, 77, self.FOLLOW_77_in_bitwiseXORExpressionNoIn1918)
                        if self._state.backtracking == 0:

                            char_literal359_tree = self._adaptor.createWithPayload(char_literal359)
                            self._adaptor.addChild(root_0, char_literal359_tree)

                        # /home/buffer/antlr/JavaScript.g:298:41: ( LT )*
                        while True: #loop179
                            alt179 = 2
                            LA179_0 = self.input.LA(1)

                            if (LA179_0 == LT) :
                                alt179 = 1


                            if alt179 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT360=self.match(self.input, LT, self.FOLLOW_LT_in_bitwiseXORExpressionNoIn1920)


                            else:
                                break #loop179
                        self._state.following.append(self.FOLLOW_bitwiseANDExpressionNoIn_in_bitwiseXORExpressionNoIn1924)
                        bitwiseANDExpressionNoIn361 = self.bitwiseANDExpressionNoIn()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, bitwiseANDExpressionNoIn361.tree)


                    else:
                        break #loop180



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 64, bitwiseXORExpressionNoIn_StartIndex, success)

            pass
        return retval

    # $ANTLR end "bitwiseXORExpressionNoIn"

    class bitwiseANDExpression_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.bitwiseANDExpression_return, self).__init__()

            self.tree = None




    # $ANTLR start "bitwiseANDExpression"
    # /home/buffer/antlr/JavaScript.g:301:1: bitwiseANDExpression : equalityExpression ( ( LT )* '&' ( LT )* equalityExpression )* ;
    def bitwiseANDExpression(self, ):

        retval = self.bitwiseANDExpression_return()
        retval.start = self.input.LT(1)
        bitwiseANDExpression_StartIndex = self.input.index()
        root_0 = None

        LT363 = None
        char_literal364 = None
        LT365 = None
        equalityExpression362 = None

        equalityExpression366 = None


        LT363_tree = None
        char_literal364_tree = None
        LT365_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 65):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:302:2: ( equalityExpression ( ( LT )* '&' ( LT )* equalityExpression )* )
                # /home/buffer/antlr/JavaScript.g:302:4: equalityExpression ( ( LT )* '&' ( LT )* equalityExpression )*
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_equalityExpression_in_bitwiseANDExpression1938)
                equalityExpression362 = self.equalityExpression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, equalityExpression362.tree)
                # /home/buffer/antlr/JavaScript.g:302:23: ( ( LT )* '&' ( LT )* equalityExpression )*
                while True: #loop183
                    alt183 = 2
                    alt183 = self.dfa183.predict(self.input)
                    if alt183 == 1:
                        # /home/buffer/antlr/JavaScript.g:302:24: ( LT )* '&' ( LT )* equalityExpression
                        pass 
                        # /home/buffer/antlr/JavaScript.g:302:26: ( LT )*
                        while True: #loop181
                            alt181 = 2
                            LA181_0 = self.input.LA(1)

                            if (LA181_0 == LT) :
                                alt181 = 1


                            if alt181 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT363=self.match(self.input, LT, self.FOLLOW_LT_in_bitwiseANDExpression1941)


                            else:
                                break #loop181
                        char_literal364=self.match(self.input, 78, self.FOLLOW_78_in_bitwiseANDExpression1945)
                        if self._state.backtracking == 0:

                            char_literal364_tree = self._adaptor.createWithPayload(char_literal364)
                            self._adaptor.addChild(root_0, char_literal364_tree)

                        # /home/buffer/antlr/JavaScript.g:302:35: ( LT )*
                        while True: #loop182
                            alt182 = 2
                            LA182_0 = self.input.LA(1)

                            if (LA182_0 == LT) :
                                alt182 = 1


                            if alt182 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT365=self.match(self.input, LT, self.FOLLOW_LT_in_bitwiseANDExpression1947)


                            else:
                                break #loop182
                        self._state.following.append(self.FOLLOW_equalityExpression_in_bitwiseANDExpression1951)
                        equalityExpression366 = self.equalityExpression()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, equalityExpression366.tree)


                    else:
                        break #loop183



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 65, bitwiseANDExpression_StartIndex, success)

            pass
        return retval

    # $ANTLR end "bitwiseANDExpression"

    class bitwiseANDExpressionNoIn_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.bitwiseANDExpressionNoIn_return, self).__init__()

            self.tree = None




    # $ANTLR start "bitwiseANDExpressionNoIn"
    # /home/buffer/antlr/JavaScript.g:305:1: bitwiseANDExpressionNoIn : equalityExpressionNoIn ( ( LT )* '&' ( LT )* equalityExpressionNoIn )* ;
    def bitwiseANDExpressionNoIn(self, ):

        retval = self.bitwiseANDExpressionNoIn_return()
        retval.start = self.input.LT(1)
        bitwiseANDExpressionNoIn_StartIndex = self.input.index()
        root_0 = None

        LT368 = None
        char_literal369 = None
        LT370 = None
        equalityExpressionNoIn367 = None

        equalityExpressionNoIn371 = None


        LT368_tree = None
        char_literal369_tree = None
        LT370_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 66):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:306:2: ( equalityExpressionNoIn ( ( LT )* '&' ( LT )* equalityExpressionNoIn )* )
                # /home/buffer/antlr/JavaScript.g:306:4: equalityExpressionNoIn ( ( LT )* '&' ( LT )* equalityExpressionNoIn )*
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_equalityExpressionNoIn_in_bitwiseANDExpressionNoIn1965)
                equalityExpressionNoIn367 = self.equalityExpressionNoIn()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, equalityExpressionNoIn367.tree)
                # /home/buffer/antlr/JavaScript.g:306:27: ( ( LT )* '&' ( LT )* equalityExpressionNoIn )*
                while True: #loop186
                    alt186 = 2
                    alt186 = self.dfa186.predict(self.input)
                    if alt186 == 1:
                        # /home/buffer/antlr/JavaScript.g:306:28: ( LT )* '&' ( LT )* equalityExpressionNoIn
                        pass 
                        # /home/buffer/antlr/JavaScript.g:306:30: ( LT )*
                        while True: #loop184
                            alt184 = 2
                            LA184_0 = self.input.LA(1)

                            if (LA184_0 == LT) :
                                alt184 = 1


                            if alt184 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT368=self.match(self.input, LT, self.FOLLOW_LT_in_bitwiseANDExpressionNoIn1968)


                            else:
                                break #loop184
                        char_literal369=self.match(self.input, 78, self.FOLLOW_78_in_bitwiseANDExpressionNoIn1972)
                        if self._state.backtracking == 0:

                            char_literal369_tree = self._adaptor.createWithPayload(char_literal369)
                            self._adaptor.addChild(root_0, char_literal369_tree)

                        # /home/buffer/antlr/JavaScript.g:306:39: ( LT )*
                        while True: #loop185
                            alt185 = 2
                            LA185_0 = self.input.LA(1)

                            if (LA185_0 == LT) :
                                alt185 = 1


                            if alt185 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT370=self.match(self.input, LT, self.FOLLOW_LT_in_bitwiseANDExpressionNoIn1974)


                            else:
                                break #loop185
                        self._state.following.append(self.FOLLOW_equalityExpressionNoIn_in_bitwiseANDExpressionNoIn1978)
                        equalityExpressionNoIn371 = self.equalityExpressionNoIn()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, equalityExpressionNoIn371.tree)


                    else:
                        break #loop186



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 66, bitwiseANDExpressionNoIn_StartIndex, success)

            pass
        return retval

    # $ANTLR end "bitwiseANDExpressionNoIn"

    class equalityExpression_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.equalityExpression_return, self).__init__()

            self.tree = None




    # $ANTLR start "equalityExpression"
    # /home/buffer/antlr/JavaScript.g:309:1: equalityExpression : relationalExpression ( ( LT )* ( '==' | '!=' | '===' | '!==' ) ( LT )* relationalExpression )* ;
    def equalityExpression(self, ):

        retval = self.equalityExpression_return()
        retval.start = self.input.LT(1)
        equalityExpression_StartIndex = self.input.index()
        root_0 = None

        LT373 = None
        set374 = None
        LT375 = None
        relationalExpression372 = None

        relationalExpression376 = None


        LT373_tree = None
        set374_tree = None
        LT375_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 67):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:310:2: ( relationalExpression ( ( LT )* ( '==' | '!=' | '===' | '!==' ) ( LT )* relationalExpression )* )
                # /home/buffer/antlr/JavaScript.g:310:4: relationalExpression ( ( LT )* ( '==' | '!=' | '===' | '!==' ) ( LT )* relationalExpression )*
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_relationalExpression_in_equalityExpression1992)
                relationalExpression372 = self.relationalExpression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, relationalExpression372.tree)
                # /home/buffer/antlr/JavaScript.g:310:25: ( ( LT )* ( '==' | '!=' | '===' | '!==' ) ( LT )* relationalExpression )*
                while True: #loop189
                    alt189 = 2
                    alt189 = self.dfa189.predict(self.input)
                    if alt189 == 1:
                        # /home/buffer/antlr/JavaScript.g:310:26: ( LT )* ( '==' | '!=' | '===' | '!==' ) ( LT )* relationalExpression
                        pass 
                        # /home/buffer/antlr/JavaScript.g:310:28: ( LT )*
                        while True: #loop187
                            alt187 = 2
                            LA187_0 = self.input.LA(1)

                            if (LA187_0 == LT) :
                                alt187 = 1


                            if alt187 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT373=self.match(self.input, LT, self.FOLLOW_LT_in_equalityExpression1995)


                            else:
                                break #loop187
                        set374 = self.input.LT(1)
                        if (79 <= self.input.LA(1) <= 82):
                            self.input.consume()
                            if self._state.backtracking == 0:
                                self._adaptor.addChild(root_0, self._adaptor.createWithPayload(set374))
                            self._state.errorRecovery = False

                        else:
                            if self._state.backtracking > 0:
                                raise BacktrackingFailed

                            mse = MismatchedSetException(None, self.input)
                            raise mse


                        # /home/buffer/antlr/JavaScript.g:310:63: ( LT )*
                        while True: #loop188
                            alt188 = 2
                            LA188_0 = self.input.LA(1)

                            if (LA188_0 == LT) :
                                alt188 = 1


                            if alt188 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT375=self.match(self.input, LT, self.FOLLOW_LT_in_equalityExpression2015)


                            else:
                                break #loop188
                        self._state.following.append(self.FOLLOW_relationalExpression_in_equalityExpression2019)
                        relationalExpression376 = self.relationalExpression()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, relationalExpression376.tree)


                    else:
                        break #loop189



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 67, equalityExpression_StartIndex, success)

            pass
        return retval

    # $ANTLR end "equalityExpression"

    class equalityExpressionNoIn_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.equalityExpressionNoIn_return, self).__init__()

            self.tree = None




    # $ANTLR start "equalityExpressionNoIn"
    # /home/buffer/antlr/JavaScript.g:313:1: equalityExpressionNoIn : relationalExpressionNoIn ( ( LT )* ( '==' | '!=' | '===' | '!==' ) ( LT )* relationalExpressionNoIn )* ;
    def equalityExpressionNoIn(self, ):

        retval = self.equalityExpressionNoIn_return()
        retval.start = self.input.LT(1)
        equalityExpressionNoIn_StartIndex = self.input.index()
        root_0 = None

        LT378 = None
        set379 = None
        LT380 = None
        relationalExpressionNoIn377 = None

        relationalExpressionNoIn381 = None


        LT378_tree = None
        set379_tree = None
        LT380_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 68):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:314:2: ( relationalExpressionNoIn ( ( LT )* ( '==' | '!=' | '===' | '!==' ) ( LT )* relationalExpressionNoIn )* )
                # /home/buffer/antlr/JavaScript.g:314:4: relationalExpressionNoIn ( ( LT )* ( '==' | '!=' | '===' | '!==' ) ( LT )* relationalExpressionNoIn )*
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_relationalExpressionNoIn_in_equalityExpressionNoIn2032)
                relationalExpressionNoIn377 = self.relationalExpressionNoIn()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, relationalExpressionNoIn377.tree)
                # /home/buffer/antlr/JavaScript.g:314:29: ( ( LT )* ( '==' | '!=' | '===' | '!==' ) ( LT )* relationalExpressionNoIn )*
                while True: #loop192
                    alt192 = 2
                    alt192 = self.dfa192.predict(self.input)
                    if alt192 == 1:
                        # /home/buffer/antlr/JavaScript.g:314:30: ( LT )* ( '==' | '!=' | '===' | '!==' ) ( LT )* relationalExpressionNoIn
                        pass 
                        # /home/buffer/antlr/JavaScript.g:314:32: ( LT )*
                        while True: #loop190
                            alt190 = 2
                            LA190_0 = self.input.LA(1)

                            if (LA190_0 == LT) :
                                alt190 = 1


                            if alt190 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT378=self.match(self.input, LT, self.FOLLOW_LT_in_equalityExpressionNoIn2035)


                            else:
                                break #loop190
                        set379 = self.input.LT(1)
                        if (79 <= self.input.LA(1) <= 82):
                            self.input.consume()
                            if self._state.backtracking == 0:
                                self._adaptor.addChild(root_0, self._adaptor.createWithPayload(set379))
                            self._state.errorRecovery = False

                        else:
                            if self._state.backtracking > 0:
                                raise BacktrackingFailed

                            mse = MismatchedSetException(None, self.input)
                            raise mse


                        # /home/buffer/antlr/JavaScript.g:314:67: ( LT )*
                        while True: #loop191
                            alt191 = 2
                            LA191_0 = self.input.LA(1)

                            if (LA191_0 == LT) :
                                alt191 = 1


                            if alt191 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT380=self.match(self.input, LT, self.FOLLOW_LT_in_equalityExpressionNoIn2055)


                            else:
                                break #loop191
                        self._state.following.append(self.FOLLOW_relationalExpressionNoIn_in_equalityExpressionNoIn2059)
                        relationalExpressionNoIn381 = self.relationalExpressionNoIn()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, relationalExpressionNoIn381.tree)


                    else:
                        break #loop192



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 68, equalityExpressionNoIn_StartIndex, success)

            pass
        return retval

    # $ANTLR end "equalityExpressionNoIn"

    class relationalExpression_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.relationalExpression_return, self).__init__()

            self.tree = None




    # $ANTLR start "relationalExpression"
    # /home/buffer/antlr/JavaScript.g:317:1: relationalExpression : shiftExpression ( ( LT )* ( '<' | '>' | '<=' | '>=' | 'instanceof' | 'in' ) ( LT )* shiftExpression )* ;
    def relationalExpression(self, ):

        retval = self.relationalExpression_return()
        retval.start = self.input.LT(1)
        relationalExpression_StartIndex = self.input.index()
        root_0 = None

        LT383 = None
        set384 = None
        LT385 = None
        shiftExpression382 = None

        shiftExpression386 = None


        LT383_tree = None
        set384_tree = None
        LT385_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 69):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:318:2: ( shiftExpression ( ( LT )* ( '<' | '>' | '<=' | '>=' | 'instanceof' | 'in' ) ( LT )* shiftExpression )* )
                # /home/buffer/antlr/JavaScript.g:318:4: shiftExpression ( ( LT )* ( '<' | '>' | '<=' | '>=' | 'instanceof' | 'in' ) ( LT )* shiftExpression )*
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_shiftExpression_in_relationalExpression2073)
                shiftExpression382 = self.shiftExpression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, shiftExpression382.tree)
                # /home/buffer/antlr/JavaScript.g:318:20: ( ( LT )* ( '<' | '>' | '<=' | '>=' | 'instanceof' | 'in' ) ( LT )* shiftExpression )*
                while True: #loop195
                    alt195 = 2
                    alt195 = self.dfa195.predict(self.input)
                    if alt195 == 1:
                        # /home/buffer/antlr/JavaScript.g:318:21: ( LT )* ( '<' | '>' | '<=' | '>=' | 'instanceof' | 'in' ) ( LT )* shiftExpression
                        pass 
                        # /home/buffer/antlr/JavaScript.g:318:23: ( LT )*
                        while True: #loop193
                            alt193 = 2
                            LA193_0 = self.input.LA(1)

                            if (LA193_0 == LT) :
                                alt193 = 1


                            if alt193 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT383=self.match(self.input, LT, self.FOLLOW_LT_in_relationalExpression2076)


                            else:
                                break #loop193
                        set384 = self.input.LT(1)
                        if self.input.LA(1) == 45 or (83 <= self.input.LA(1) <= 87):
                            self.input.consume()
                            if self._state.backtracking == 0:
                                self._adaptor.addChild(root_0, self._adaptor.createWithPayload(set384))
                            self._state.errorRecovery = False

                        else:
                            if self._state.backtracking > 0:
                                raise BacktrackingFailed

                            mse = MismatchedSetException(None, self.input)
                            raise mse


                        # /home/buffer/antlr/JavaScript.g:318:76: ( LT )*
                        while True: #loop194
                            alt194 = 2
                            LA194_0 = self.input.LA(1)

                            if (LA194_0 == LT) :
                                alt194 = 1


                            if alt194 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT385=self.match(self.input, LT, self.FOLLOW_LT_in_relationalExpression2104)


                            else:
                                break #loop194
                        self._state.following.append(self.FOLLOW_shiftExpression_in_relationalExpression2108)
                        shiftExpression386 = self.shiftExpression()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, shiftExpression386.tree)


                    else:
                        break #loop195



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 69, relationalExpression_StartIndex, success)

            pass
        return retval

    # $ANTLR end "relationalExpression"

    class relationalExpressionNoIn_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.relationalExpressionNoIn_return, self).__init__()

            self.tree = None




    # $ANTLR start "relationalExpressionNoIn"
    # /home/buffer/antlr/JavaScript.g:321:1: relationalExpressionNoIn : shiftExpression ( ( LT )* ( '<' | '>' | '<=' | '>=' | 'instanceof' ) ( LT )* shiftExpression )* ;
    def relationalExpressionNoIn(self, ):

        retval = self.relationalExpressionNoIn_return()
        retval.start = self.input.LT(1)
        relationalExpressionNoIn_StartIndex = self.input.index()
        root_0 = None

        LT388 = None
        set389 = None
        LT390 = None
        shiftExpression387 = None

        shiftExpression391 = None


        LT388_tree = None
        set389_tree = None
        LT390_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 70):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:322:2: ( shiftExpression ( ( LT )* ( '<' | '>' | '<=' | '>=' | 'instanceof' ) ( LT )* shiftExpression )* )
                # /home/buffer/antlr/JavaScript.g:322:4: shiftExpression ( ( LT )* ( '<' | '>' | '<=' | '>=' | 'instanceof' ) ( LT )* shiftExpression )*
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_shiftExpression_in_relationalExpressionNoIn2121)
                shiftExpression387 = self.shiftExpression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, shiftExpression387.tree)
                # /home/buffer/antlr/JavaScript.g:322:20: ( ( LT )* ( '<' | '>' | '<=' | '>=' | 'instanceof' ) ( LT )* shiftExpression )*
                while True: #loop198
                    alt198 = 2
                    alt198 = self.dfa198.predict(self.input)
                    if alt198 == 1:
                        # /home/buffer/antlr/JavaScript.g:322:21: ( LT )* ( '<' | '>' | '<=' | '>=' | 'instanceof' ) ( LT )* shiftExpression
                        pass 
                        # /home/buffer/antlr/JavaScript.g:322:23: ( LT )*
                        while True: #loop196
                            alt196 = 2
                            LA196_0 = self.input.LA(1)

                            if (LA196_0 == LT) :
                                alt196 = 1


                            if alt196 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT388=self.match(self.input, LT, self.FOLLOW_LT_in_relationalExpressionNoIn2124)


                            else:
                                break #loop196
                        set389 = self.input.LT(1)
                        if (83 <= self.input.LA(1) <= 87):
                            self.input.consume()
                            if self._state.backtracking == 0:
                                self._adaptor.addChild(root_0, self._adaptor.createWithPayload(set389))
                            self._state.errorRecovery = False

                        else:
                            if self._state.backtracking > 0:
                                raise BacktrackingFailed

                            mse = MismatchedSetException(None, self.input)
                            raise mse


                        # /home/buffer/antlr/JavaScript.g:322:69: ( LT )*
                        while True: #loop197
                            alt197 = 2
                            LA197_0 = self.input.LA(1)

                            if (LA197_0 == LT) :
                                alt197 = 1


                            if alt197 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT390=self.match(self.input, LT, self.FOLLOW_LT_in_relationalExpressionNoIn2148)


                            else:
                                break #loop197
                        self._state.following.append(self.FOLLOW_shiftExpression_in_relationalExpressionNoIn2152)
                        shiftExpression391 = self.shiftExpression()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, shiftExpression391.tree)


                    else:
                        break #loop198



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 70, relationalExpressionNoIn_StartIndex, success)

            pass
        return retval

    # $ANTLR end "relationalExpressionNoIn"

    class shiftExpression_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.shiftExpression_return, self).__init__()

            self.tree = None




    # $ANTLR start "shiftExpression"
    # /home/buffer/antlr/JavaScript.g:325:1: shiftExpression : additiveExpression ( ( LT )* ( '<<' | '>>' | '>>>' ) ( LT )* additiveExpression )* ;
    def shiftExpression(self, ):

        retval = self.shiftExpression_return()
        retval.start = self.input.LT(1)
        shiftExpression_StartIndex = self.input.index()
        root_0 = None

        LT393 = None
        set394 = None
        LT395 = None
        additiveExpression392 = None

        additiveExpression396 = None


        LT393_tree = None
        set394_tree = None
        LT395_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 71):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:326:2: ( additiveExpression ( ( LT )* ( '<<' | '>>' | '>>>' ) ( LT )* additiveExpression )* )
                # /home/buffer/antlr/JavaScript.g:326:4: additiveExpression ( ( LT )* ( '<<' | '>>' | '>>>' ) ( LT )* additiveExpression )*
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_additiveExpression_in_shiftExpression2165)
                additiveExpression392 = self.additiveExpression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, additiveExpression392.tree)
                # /home/buffer/antlr/JavaScript.g:326:23: ( ( LT )* ( '<<' | '>>' | '>>>' ) ( LT )* additiveExpression )*
                while True: #loop201
                    alt201 = 2
                    alt201 = self.dfa201.predict(self.input)
                    if alt201 == 1:
                        # /home/buffer/antlr/JavaScript.g:326:24: ( LT )* ( '<<' | '>>' | '>>>' ) ( LT )* additiveExpression
                        pass 
                        # /home/buffer/antlr/JavaScript.g:326:26: ( LT )*
                        while True: #loop199
                            alt199 = 2
                            LA199_0 = self.input.LA(1)

                            if (LA199_0 == LT) :
                                alt199 = 1


                            if alt199 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT393=self.match(self.input, LT, self.FOLLOW_LT_in_shiftExpression2168)


                            else:
                                break #loop199
                        set394 = self.input.LT(1)
                        if (88 <= self.input.LA(1) <= 90):
                            self.input.consume()
                            if self._state.backtracking == 0:
                                self._adaptor.addChild(root_0, self._adaptor.createWithPayload(set394))
                            self._state.errorRecovery = False

                        else:
                            if self._state.backtracking > 0:
                                raise BacktrackingFailed

                            mse = MismatchedSetException(None, self.input)
                            raise mse


                        # /home/buffer/antlr/JavaScript.g:326:53: ( LT )*
                        while True: #loop200
                            alt200 = 2
                            LA200_0 = self.input.LA(1)

                            if (LA200_0 == LT) :
                                alt200 = 1


                            if alt200 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT395=self.match(self.input, LT, self.FOLLOW_LT_in_shiftExpression2184)


                            else:
                                break #loop200
                        self._state.following.append(self.FOLLOW_additiveExpression_in_shiftExpression2188)
                        additiveExpression396 = self.additiveExpression()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, additiveExpression396.tree)


                    else:
                        break #loop201



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 71, shiftExpression_StartIndex, success)

            pass
        return retval

    # $ANTLR end "shiftExpression"

    class additiveExpression_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.additiveExpression_return, self).__init__()

            self.tree = None




    # $ANTLR start "additiveExpression"
    # /home/buffer/antlr/JavaScript.g:329:1: additiveExpression : multiplicativeExpression ( ( LT )* ( '+' | '-' ) ( LT )* multiplicativeExpression )* ;
    def additiveExpression(self, ):

        retval = self.additiveExpression_return()
        retval.start = self.input.LT(1)
        additiveExpression_StartIndex = self.input.index()
        root_0 = None

        LT398 = None
        set399 = None
        LT400 = None
        multiplicativeExpression397 = None

        multiplicativeExpression401 = None


        LT398_tree = None
        set399_tree = None
        LT400_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 72):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:330:2: ( multiplicativeExpression ( ( LT )* ( '+' | '-' ) ( LT )* multiplicativeExpression )* )
                # /home/buffer/antlr/JavaScript.g:330:4: multiplicativeExpression ( ( LT )* ( '+' | '-' ) ( LT )* multiplicativeExpression )*
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_multiplicativeExpression_in_additiveExpression2201)
                multiplicativeExpression397 = self.multiplicativeExpression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, multiplicativeExpression397.tree)
                # /home/buffer/antlr/JavaScript.g:330:29: ( ( LT )* ( '+' | '-' ) ( LT )* multiplicativeExpression )*
                while True: #loop204
                    alt204 = 2
                    alt204 = self.dfa204.predict(self.input)
                    if alt204 == 1:
                        # /home/buffer/antlr/JavaScript.g:330:30: ( LT )* ( '+' | '-' ) ( LT )* multiplicativeExpression
                        pass 
                        # /home/buffer/antlr/JavaScript.g:330:32: ( LT )*
                        while True: #loop202
                            alt202 = 2
                            LA202_0 = self.input.LA(1)

                            if (LA202_0 == LT) :
                                alt202 = 1


                            if alt202 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT398=self.match(self.input, LT, self.FOLLOW_LT_in_additiveExpression2204)


                            else:
                                break #loop202
                        set399 = self.input.LT(1)
                        if (91 <= self.input.LA(1) <= 92):
                            self.input.consume()
                            if self._state.backtracking == 0:
                                self._adaptor.addChild(root_0, self._adaptor.createWithPayload(set399))
                            self._state.errorRecovery = False

                        else:
                            if self._state.backtracking > 0:
                                raise BacktrackingFailed

                            mse = MismatchedSetException(None, self.input)
                            raise mse


                        # /home/buffer/antlr/JavaScript.g:330:49: ( LT )*
                        while True: #loop203
                            alt203 = 2
                            LA203_0 = self.input.LA(1)

                            if (LA203_0 == LT) :
                                alt203 = 1


                            if alt203 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT400=self.match(self.input, LT, self.FOLLOW_LT_in_additiveExpression2216)


                            else:
                                break #loop203
                        self._state.following.append(self.FOLLOW_multiplicativeExpression_in_additiveExpression2220)
                        multiplicativeExpression401 = self.multiplicativeExpression()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, multiplicativeExpression401.tree)


                    else:
                        break #loop204



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 72, additiveExpression_StartIndex, success)

            pass
        return retval

    # $ANTLR end "additiveExpression"

    class multiplicativeExpression_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.multiplicativeExpression_return, self).__init__()

            self.tree = None




    # $ANTLR start "multiplicativeExpression"
    # /home/buffer/antlr/JavaScript.g:333:1: multiplicativeExpression : unaryExpression ( ( LT )* ( '*' | '/' | '%' ) ( LT )* unaryExpression )* ;
    def multiplicativeExpression(self, ):

        retval = self.multiplicativeExpression_return()
        retval.start = self.input.LT(1)
        multiplicativeExpression_StartIndex = self.input.index()
        root_0 = None

        LT403 = None
        set404 = None
        LT405 = None
        unaryExpression402 = None

        unaryExpression406 = None


        LT403_tree = None
        set404_tree = None
        LT405_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 73):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:334:2: ( unaryExpression ( ( LT )* ( '*' | '/' | '%' ) ( LT )* unaryExpression )* )
                # /home/buffer/antlr/JavaScript.g:334:4: unaryExpression ( ( LT )* ( '*' | '/' | '%' ) ( LT )* unaryExpression )*
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_unaryExpression_in_multiplicativeExpression2233)
                unaryExpression402 = self.unaryExpression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, unaryExpression402.tree)
                # /home/buffer/antlr/JavaScript.g:334:20: ( ( LT )* ( '*' | '/' | '%' ) ( LT )* unaryExpression )*
                while True: #loop207
                    alt207 = 2
                    alt207 = self.dfa207.predict(self.input)
                    if alt207 == 1:
                        # /home/buffer/antlr/JavaScript.g:334:21: ( LT )* ( '*' | '/' | '%' ) ( LT )* unaryExpression
                        pass 
                        # /home/buffer/antlr/JavaScript.g:334:23: ( LT )*
                        while True: #loop205
                            alt205 = 2
                            LA205_0 = self.input.LA(1)

                            if (LA205_0 == LT) :
                                alt205 = 1


                            if alt205 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT403=self.match(self.input, LT, self.FOLLOW_LT_in_multiplicativeExpression2236)


                            else:
                                break #loop205
                        set404 = self.input.LT(1)
                        if (93 <= self.input.LA(1) <= 95):
                            self.input.consume()
                            if self._state.backtracking == 0:
                                self._adaptor.addChild(root_0, self._adaptor.createWithPayload(set404))
                            self._state.errorRecovery = False

                        else:
                            if self._state.backtracking > 0:
                                raise BacktrackingFailed

                            mse = MismatchedSetException(None, self.input)
                            raise mse


                        # /home/buffer/antlr/JavaScript.g:334:46: ( LT )*
                        while True: #loop206
                            alt206 = 2
                            LA206_0 = self.input.LA(1)

                            if (LA206_0 == LT) :
                                alt206 = 1


                            if alt206 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT405=self.match(self.input, LT, self.FOLLOW_LT_in_multiplicativeExpression2252)


                            else:
                                break #loop206
                        self._state.following.append(self.FOLLOW_unaryExpression_in_multiplicativeExpression2256)
                        unaryExpression406 = self.unaryExpression()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, unaryExpression406.tree)


                    else:
                        break #loop207



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 73, multiplicativeExpression_StartIndex, success)

            pass
        return retval

    # $ANTLR end "multiplicativeExpression"

    class unaryExpression_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.unaryExpression_return, self).__init__()

            self.tree = None




    # $ANTLR start "unaryExpression"
    # /home/buffer/antlr/JavaScript.g:337:1: unaryExpression : ( postfixExpression | ( 'delete' | 'void' | 'typeof' | '++' | '--' | '+' | '-' | '~' | '!' ) unaryExpression );
    def unaryExpression(self, ):

        retval = self.unaryExpression_return()
        retval.start = self.input.LT(1)
        unaryExpression_StartIndex = self.input.index()
        root_0 = None

        set408 = None
        postfixExpression407 = None

        unaryExpression409 = None


        set408_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 74):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:338:2: ( postfixExpression | ( 'delete' | 'void' | 'typeof' | '++' | '--' | '+' | '-' | '~' | '!' ) unaryExpression )
                alt208 = 2
                LA208_0 = self.input.LA(1)

                if ((Identifier <= LA208_0 <= NumericLiteral) or (31 <= LA208_0 <= 32) or LA208_0 == 35 or (58 <= LA208_0 <= 59) or (103 <= LA208_0 <= 106)) :
                    alt208 = 1
                elif ((91 <= LA208_0 <= 92) or (96 <= LA208_0 <= 102)) :
                    alt208 = 2
                else:
                    if self._state.backtracking > 0:
                        raise BacktrackingFailed

                    nvae = NoViableAltException("", 208, 0, self.input)

                    raise nvae

                if alt208 == 1:
                    # /home/buffer/antlr/JavaScript.g:338:4: postfixExpression
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_postfixExpression_in_unaryExpression2269)
                    postfixExpression407 = self.postfixExpression()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, postfixExpression407.tree)


                elif alt208 == 2:
                    # /home/buffer/antlr/JavaScript.g:339:4: ( 'delete' | 'void' | 'typeof' | '++' | '--' | '+' | '-' | '~' | '!' ) unaryExpression
                    pass 
                    root_0 = self._adaptor.nil()

                    set408 = self.input.LT(1)
                    if (91 <= self.input.LA(1) <= 92) or (96 <= self.input.LA(1) <= 102):
                        self.input.consume()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, self._adaptor.createWithPayload(set408))
                        self._state.errorRecovery = False

                    else:
                        if self._state.backtracking > 0:
                            raise BacktrackingFailed

                        mse = MismatchedSetException(None, self.input)
                        raise mse


                    self._state.following.append(self.FOLLOW_unaryExpression_in_unaryExpression2310)
                    unaryExpression409 = self.unaryExpression()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, unaryExpression409.tree)


                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 74, unaryExpression_StartIndex, success)

            pass
        return retval

    # $ANTLR end "unaryExpression"

    class postfixExpression_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.postfixExpression_return, self).__init__()

            self.tree = None




    # $ANTLR start "postfixExpression"
    # /home/buffer/antlr/JavaScript.g:342:1: postfixExpression : leftHandSideExpression ( '++' | '--' )? ;
    def postfixExpression(self, ):

        retval = self.postfixExpression_return()
        retval.start = self.input.LT(1)
        postfixExpression_StartIndex = self.input.index()
        root_0 = None

        set411 = None
        leftHandSideExpression410 = None


        set411_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 75):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:343:2: ( leftHandSideExpression ( '++' | '--' )? )
                # /home/buffer/antlr/JavaScript.g:343:4: leftHandSideExpression ( '++' | '--' )?
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_leftHandSideExpression_in_postfixExpression2322)
                leftHandSideExpression410 = self.leftHandSideExpression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, leftHandSideExpression410.tree)
                # /home/buffer/antlr/JavaScript.g:343:27: ( '++' | '--' )?
                alt209 = 2
                LA209_0 = self.input.LA(1)

                if ((99 <= LA209_0 <= 100)) :
                    alt209 = 1
                if alt209 == 1:
                    # /home/buffer/antlr/JavaScript.g:
                    pass 
                    set411 = self.input.LT(1)
                    if (99 <= self.input.LA(1) <= 100):
                        self.input.consume()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, self._adaptor.createWithPayload(set411))
                        self._state.errorRecovery = False

                    else:
                        if self._state.backtracking > 0:
                            raise BacktrackingFailed

                        mse = MismatchedSetException(None, self.input)
                        raise mse








                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 75, postfixExpression_StartIndex, success)

            pass
        return retval

    # $ANTLR end "postfixExpression"

    class primaryExpression_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.primaryExpression_return, self).__init__()

            self.tree = None




    # $ANTLR start "primaryExpression"
    # /home/buffer/antlr/JavaScript.g:346:1: primaryExpression : ( 'this' | Identifier | literal | arrayLiteral | objectLiteral | '(' ( LT )* expression ( LT )* ')' );
    def primaryExpression(self, ):

        retval = self.primaryExpression_return()
        retval.start = self.input.LT(1)
        primaryExpression_StartIndex = self.input.index()
        root_0 = None

        string_literal412 = None
        Identifier413 = None
        char_literal417 = None
        LT418 = None
        LT420 = None
        char_literal421 = None
        literal414 = None

        arrayLiteral415 = None

        objectLiteral416 = None

        expression419 = None


        string_literal412_tree = None
        Identifier413_tree = None
        char_literal417_tree = None
        LT418_tree = None
        LT420_tree = None
        char_literal421_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 76):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:347:2: ( 'this' | Identifier | literal | arrayLiteral | objectLiteral | '(' ( LT )* expression ( LT )* ')' )
                alt212 = 6
                LA212 = self.input.LA(1)
                if LA212 == 103:
                    alt212 = 1
                elif LA212 == Identifier:
                    alt212 = 2
                elif LA212 == StringLiteral or LA212 == NumericLiteral or LA212 == 104 or LA212 == 105 or LA212 == 106:
                    alt212 = 3
                elif LA212 == 59:
                    alt212 = 4
                elif LA212 == 35:
                    alt212 = 5
                elif LA212 == 32:
                    alt212 = 6
                else:
                    if self._state.backtracking > 0:
                        raise BacktrackingFailed

                    nvae = NoViableAltException("", 212, 0, self.input)

                    raise nvae

                if alt212 == 1:
                    # /home/buffer/antlr/JavaScript.g:347:4: 'this'
                    pass 
                    root_0 = self._adaptor.nil()

                    string_literal412=self.match(self.input, 103, self.FOLLOW_103_in_primaryExpression2342)
                    if self._state.backtracking == 0:

                        string_literal412_tree = self._adaptor.createWithPayload(string_literal412)
                        self._adaptor.addChild(root_0, string_literal412_tree)



                elif alt212 == 2:
                    # /home/buffer/antlr/JavaScript.g:348:4: Identifier
                    pass 
                    root_0 = self._adaptor.nil()

                    Identifier413=self.match(self.input, Identifier, self.FOLLOW_Identifier_in_primaryExpression2347)
                    if self._state.backtracking == 0:

                        Identifier413_tree = self._adaptor.createWithPayload(Identifier413)
                        self._adaptor.addChild(root_0, Identifier413_tree)



                elif alt212 == 3:
                    # /home/buffer/antlr/JavaScript.g:349:4: literal
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_literal_in_primaryExpression2352)
                    literal414 = self.literal()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, literal414.tree)


                elif alt212 == 4:
                    # /home/buffer/antlr/JavaScript.g:350:4: arrayLiteral
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_arrayLiteral_in_primaryExpression2357)
                    arrayLiteral415 = self.arrayLiteral()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, arrayLiteral415.tree)


                elif alt212 == 5:
                    # /home/buffer/antlr/JavaScript.g:351:4: objectLiteral
                    pass 
                    root_0 = self._adaptor.nil()

                    self._state.following.append(self.FOLLOW_objectLiteral_in_primaryExpression2362)
                    objectLiteral416 = self.objectLiteral()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, objectLiteral416.tree)


                elif alt212 == 6:
                    # /home/buffer/antlr/JavaScript.g:352:4: '(' ( LT )* expression ( LT )* ')'
                    pass 
                    root_0 = self._adaptor.nil()

                    char_literal417=self.match(self.input, 32, self.FOLLOW_32_in_primaryExpression2367)
                    if self._state.backtracking == 0:

                        char_literal417_tree = self._adaptor.createWithPayload(char_literal417)
                        self._adaptor.addChild(root_0, char_literal417_tree)

                    # /home/buffer/antlr/JavaScript.g:352:10: ( LT )*
                    while True: #loop210
                        alt210 = 2
                        LA210_0 = self.input.LA(1)

                        if (LA210_0 == LT) :
                            alt210 = 1


                        if alt210 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT418=self.match(self.input, LT, self.FOLLOW_LT_in_primaryExpression2369)


                        else:
                            break #loop210
                    self._state.following.append(self.FOLLOW_expression_in_primaryExpression2373)
                    expression419 = self.expression()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, expression419.tree)
                    # /home/buffer/antlr/JavaScript.g:352:26: ( LT )*
                    while True: #loop211
                        alt211 = 2
                        LA211_0 = self.input.LA(1)

                        if (LA211_0 == LT) :
                            alt211 = 1


                        if alt211 == 1:
                            # /home/buffer/antlr/JavaScript.g:0:0: LT
                            pass 
                            LT420=self.match(self.input, LT, self.FOLLOW_LT_in_primaryExpression2375)


                        else:
                            break #loop211
                    char_literal421=self.match(self.input, 34, self.FOLLOW_34_in_primaryExpression2379)
                    if self._state.backtracking == 0:

                        char_literal421_tree = self._adaptor.createWithPayload(char_literal421)
                        self._adaptor.addChild(root_0, char_literal421_tree)



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 76, primaryExpression_StartIndex, success)

            pass
        return retval

    # $ANTLR end "primaryExpression"

    class arrayLiteral_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.arrayLiteral_return, self).__init__()

            self.tree = None




    # $ANTLR start "arrayLiteral"
    # /home/buffer/antlr/JavaScript.g:356:1: arrayLiteral : '[' ( LT )* ( assignmentExpression )? ( ( LT )* ',' ( ( LT )* assignmentExpression )? )* ( LT )* ']' ;
    def arrayLiteral(self, ):

        retval = self.arrayLiteral_return()
        retval.start = self.input.LT(1)
        arrayLiteral_StartIndex = self.input.index()
        root_0 = None

        char_literal422 = None
        LT423 = None
        LT425 = None
        char_literal426 = None
        LT427 = None
        LT429 = None
        char_literal430 = None
        assignmentExpression424 = None

        assignmentExpression428 = None


        char_literal422_tree = None
        LT423_tree = None
        LT425_tree = None
        char_literal426_tree = None
        LT427_tree = None
        LT429_tree = None
        char_literal430_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 77):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:357:2: ( '[' ( LT )* ( assignmentExpression )? ( ( LT )* ',' ( ( LT )* assignmentExpression )? )* ( LT )* ']' )
                # /home/buffer/antlr/JavaScript.g:357:4: '[' ( LT )* ( assignmentExpression )? ( ( LT )* ',' ( ( LT )* assignmentExpression )? )* ( LT )* ']'
                pass 
                root_0 = self._adaptor.nil()

                char_literal422=self.match(self.input, 59, self.FOLLOW_59_in_arrayLiteral2392)
                if self._state.backtracking == 0:

                    char_literal422_tree = self._adaptor.createWithPayload(char_literal422)
                    self._adaptor.addChild(root_0, char_literal422_tree)

                # /home/buffer/antlr/JavaScript.g:357:10: ( LT )*
                while True: #loop213
                    alt213 = 2
                    LA213_0 = self.input.LA(1)

                    if (LA213_0 == LT) :
                        LA213_2 = self.input.LA(2)

                        if (self.synpred280_JavaScript()) :
                            alt213 = 1




                    if alt213 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT423=self.match(self.input, LT, self.FOLLOW_LT_in_arrayLiteral2394)


                    else:
                        break #loop213
                # /home/buffer/antlr/JavaScript.g:357:13: ( assignmentExpression )?
                alt214 = 2
                LA214_0 = self.input.LA(1)

                if ((Identifier <= LA214_0 <= NumericLiteral) or (31 <= LA214_0 <= 32) or LA214_0 == 35 or (58 <= LA214_0 <= 59) or (91 <= LA214_0 <= 92) or (96 <= LA214_0 <= 106)) :
                    alt214 = 1
                if alt214 == 1:
                    # /home/buffer/antlr/JavaScript.g:0:0: assignmentExpression
                    pass 
                    self._state.following.append(self.FOLLOW_assignmentExpression_in_arrayLiteral2398)
                    assignmentExpression424 = self.assignmentExpression()

                    self._state.following.pop()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, assignmentExpression424.tree)



                # /home/buffer/antlr/JavaScript.g:357:35: ( ( LT )* ',' ( ( LT )* assignmentExpression )? )*
                while True: #loop218
                    alt218 = 2
                    alt218 = self.dfa218.predict(self.input)
                    if alt218 == 1:
                        # /home/buffer/antlr/JavaScript.g:357:36: ( LT )* ',' ( ( LT )* assignmentExpression )?
                        pass 
                        # /home/buffer/antlr/JavaScript.g:357:38: ( LT )*
                        while True: #loop215
                            alt215 = 2
                            LA215_0 = self.input.LA(1)

                            if (LA215_0 == LT) :
                                alt215 = 1


                            if alt215 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT425=self.match(self.input, LT, self.FOLLOW_LT_in_arrayLiteral2402)


                            else:
                                break #loop215
                        char_literal426=self.match(self.input, 33, self.FOLLOW_33_in_arrayLiteral2406)
                        if self._state.backtracking == 0:

                            char_literal426_tree = self._adaptor.createWithPayload(char_literal426)
                            self._adaptor.addChild(root_0, char_literal426_tree)

                        # /home/buffer/antlr/JavaScript.g:357:45: ( ( LT )* assignmentExpression )?
                        alt217 = 2
                        alt217 = self.dfa217.predict(self.input)
                        if alt217 == 1:
                            # /home/buffer/antlr/JavaScript.g:357:46: ( LT )* assignmentExpression
                            pass 
                            # /home/buffer/antlr/JavaScript.g:357:48: ( LT )*
                            while True: #loop216
                                alt216 = 2
                                LA216_0 = self.input.LA(1)

                                if (LA216_0 == LT) :
                                    alt216 = 1


                                if alt216 == 1:
                                    # /home/buffer/antlr/JavaScript.g:0:0: LT
                                    pass 
                                    LT427=self.match(self.input, LT, self.FOLLOW_LT_in_arrayLiteral2409)


                                else:
                                    break #loop216
                            self._state.following.append(self.FOLLOW_assignmentExpression_in_arrayLiteral2413)
                            assignmentExpression428 = self.assignmentExpression()

                            self._state.following.pop()
                            if self._state.backtracking == 0:
                                self._adaptor.addChild(root_0, assignmentExpression428.tree)





                    else:
                        break #loop218
                # /home/buffer/antlr/JavaScript.g:357:78: ( LT )*
                while True: #loop219
                    alt219 = 2
                    LA219_0 = self.input.LA(1)

                    if (LA219_0 == LT) :
                        alt219 = 1


                    if alt219 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT429=self.match(self.input, LT, self.FOLLOW_LT_in_arrayLiteral2419)


                    else:
                        break #loop219
                char_literal430=self.match(self.input, 60, self.FOLLOW_60_in_arrayLiteral2423)
                if self._state.backtracking == 0:

                    char_literal430_tree = self._adaptor.createWithPayload(char_literal430)
                    self._adaptor.addChild(root_0, char_literal430_tree)




                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 77, arrayLiteral_StartIndex, success)

            pass
        return retval

    # $ANTLR end "arrayLiteral"

    class objectLiteral_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.objectLiteral_return, self).__init__()

            self.tree = None




    # $ANTLR start "objectLiteral"
    # /home/buffer/antlr/JavaScript.g:361:1: objectLiteral : '{' ( LT )* propertyNameAndValue ( ( LT )* ',' ( LT )* propertyNameAndValue )* ( LT )* '}' ;
    def objectLiteral(self, ):

        retval = self.objectLiteral_return()
        retval.start = self.input.LT(1)
        objectLiteral_StartIndex = self.input.index()
        root_0 = None

        char_literal431 = None
        LT432 = None
        LT434 = None
        char_literal435 = None
        LT436 = None
        LT438 = None
        char_literal439 = None
        propertyNameAndValue433 = None

        propertyNameAndValue437 = None


        char_literal431_tree = None
        LT432_tree = None
        LT434_tree = None
        char_literal435_tree = None
        LT436_tree = None
        LT438_tree = None
        char_literal439_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 78):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:362:2: ( '{' ( LT )* propertyNameAndValue ( ( LT )* ',' ( LT )* propertyNameAndValue )* ( LT )* '}' )
                # /home/buffer/antlr/JavaScript.g:362:4: '{' ( LT )* propertyNameAndValue ( ( LT )* ',' ( LT )* propertyNameAndValue )* ( LT )* '}'
                pass 
                root_0 = self._adaptor.nil()

                char_literal431=self.match(self.input, 35, self.FOLLOW_35_in_objectLiteral2442)
                if self._state.backtracking == 0:

                    char_literal431_tree = self._adaptor.createWithPayload(char_literal431)
                    self._adaptor.addChild(root_0, char_literal431_tree)

                # /home/buffer/antlr/JavaScript.g:362:10: ( LT )*
                while True: #loop220
                    alt220 = 2
                    LA220_0 = self.input.LA(1)

                    if (LA220_0 == LT) :
                        alt220 = 1


                    if alt220 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT432=self.match(self.input, LT, self.FOLLOW_LT_in_objectLiteral2444)


                    else:
                        break #loop220
                self._state.following.append(self.FOLLOW_propertyNameAndValue_in_objectLiteral2448)
                propertyNameAndValue433 = self.propertyNameAndValue()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, propertyNameAndValue433.tree)
                # /home/buffer/antlr/JavaScript.g:362:34: ( ( LT )* ',' ( LT )* propertyNameAndValue )*
                while True: #loop223
                    alt223 = 2
                    alt223 = self.dfa223.predict(self.input)
                    if alt223 == 1:
                        # /home/buffer/antlr/JavaScript.g:362:35: ( LT )* ',' ( LT )* propertyNameAndValue
                        pass 
                        # /home/buffer/antlr/JavaScript.g:362:37: ( LT )*
                        while True: #loop221
                            alt221 = 2
                            LA221_0 = self.input.LA(1)

                            if (LA221_0 == LT) :
                                alt221 = 1


                            if alt221 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT434=self.match(self.input, LT, self.FOLLOW_LT_in_objectLiteral2451)


                            else:
                                break #loop221
                        char_literal435=self.match(self.input, 33, self.FOLLOW_33_in_objectLiteral2455)
                        if self._state.backtracking == 0:

                            char_literal435_tree = self._adaptor.createWithPayload(char_literal435)
                            self._adaptor.addChild(root_0, char_literal435_tree)

                        # /home/buffer/antlr/JavaScript.g:362:46: ( LT )*
                        while True: #loop222
                            alt222 = 2
                            LA222_0 = self.input.LA(1)

                            if (LA222_0 == LT) :
                                alt222 = 1


                            if alt222 == 1:
                                # /home/buffer/antlr/JavaScript.g:0:0: LT
                                pass 
                                LT436=self.match(self.input, LT, self.FOLLOW_LT_in_objectLiteral2457)


                            else:
                                break #loop222
                        self._state.following.append(self.FOLLOW_propertyNameAndValue_in_objectLiteral2461)
                        propertyNameAndValue437 = self.propertyNameAndValue()

                        self._state.following.pop()
                        if self._state.backtracking == 0:
                            self._adaptor.addChild(root_0, propertyNameAndValue437.tree)


                    else:
                        break #loop223
                # /home/buffer/antlr/JavaScript.g:362:74: ( LT )*
                while True: #loop224
                    alt224 = 2
                    LA224_0 = self.input.LA(1)

                    if (LA224_0 == LT) :
                        alt224 = 1


                    if alt224 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT438=self.match(self.input, LT, self.FOLLOW_LT_in_objectLiteral2465)


                    else:
                        break #loop224
                char_literal439=self.match(self.input, 36, self.FOLLOW_36_in_objectLiteral2469)
                if self._state.backtracking == 0:

                    char_literal439_tree = self._adaptor.createWithPayload(char_literal439)
                    self._adaptor.addChild(root_0, char_literal439_tree)




                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 78, objectLiteral_StartIndex, success)

            pass
        return retval

    # $ANTLR end "objectLiteral"

    class propertyNameAndValue_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.propertyNameAndValue_return, self).__init__()

            self.tree = None




    # $ANTLR start "propertyNameAndValue"
    # /home/buffer/antlr/JavaScript.g:365:1: propertyNameAndValue : propertyName ( LT )* ':' ( LT )* assignmentExpression ;
    def propertyNameAndValue(self, ):

        retval = self.propertyNameAndValue_return()
        retval.start = self.input.LT(1)
        propertyNameAndValue_StartIndex = self.input.index()
        root_0 = None

        LT441 = None
        char_literal442 = None
        LT443 = None
        propertyName440 = None

        assignmentExpression444 = None


        LT441_tree = None
        char_literal442_tree = None
        LT443_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 79):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:366:2: ( propertyName ( LT )* ':' ( LT )* assignmentExpression )
                # /home/buffer/antlr/JavaScript.g:366:4: propertyName ( LT )* ':' ( LT )* assignmentExpression
                pass 
                root_0 = self._adaptor.nil()

                self._state.following.append(self.FOLLOW_propertyName_in_propertyNameAndValue2481)
                propertyName440 = self.propertyName()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, propertyName440.tree)
                # /home/buffer/antlr/JavaScript.g:366:19: ( LT )*
                while True: #loop225
                    alt225 = 2
                    LA225_0 = self.input.LA(1)

                    if (LA225_0 == LT) :
                        alt225 = 1


                    if alt225 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT441=self.match(self.input, LT, self.FOLLOW_LT_in_propertyNameAndValue2483)


                    else:
                        break #loop225
                char_literal442=self.match(self.input, 50, self.FOLLOW_50_in_propertyNameAndValue2487)
                if self._state.backtracking == 0:

                    char_literal442_tree = self._adaptor.createWithPayload(char_literal442)
                    self._adaptor.addChild(root_0, char_literal442_tree)

                # /home/buffer/antlr/JavaScript.g:366:28: ( LT )*
                while True: #loop226
                    alt226 = 2
                    LA226_0 = self.input.LA(1)

                    if (LA226_0 == LT) :
                        alt226 = 1


                    if alt226 == 1:
                        # /home/buffer/antlr/JavaScript.g:0:0: LT
                        pass 
                        LT443=self.match(self.input, LT, self.FOLLOW_LT_in_propertyNameAndValue2489)


                    else:
                        break #loop226
                self._state.following.append(self.FOLLOW_assignmentExpression_in_propertyNameAndValue2493)
                assignmentExpression444 = self.assignmentExpression()

                self._state.following.pop()
                if self._state.backtracking == 0:
                    self._adaptor.addChild(root_0, assignmentExpression444.tree)



                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 79, propertyNameAndValue_StartIndex, success)

            pass
        return retval

    # $ANTLR end "propertyNameAndValue"

    class propertyName_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.propertyName_return, self).__init__()

            self.tree = None




    # $ANTLR start "propertyName"
    # /home/buffer/antlr/JavaScript.g:369:1: propertyName : ( Identifier | StringLiteral | NumericLiteral );
    def propertyName(self, ):

        retval = self.propertyName_return()
        retval.start = self.input.LT(1)
        propertyName_StartIndex = self.input.index()
        root_0 = None

        set445 = None

        set445_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 80):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:370:2: ( Identifier | StringLiteral | NumericLiteral )
                # /home/buffer/antlr/JavaScript.g:
                pass 
                root_0 = self._adaptor.nil()

                set445 = self.input.LT(1)
                if (Identifier <= self.input.LA(1) <= NumericLiteral):
                    self.input.consume()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, self._adaptor.createWithPayload(set445))
                    self._state.errorRecovery = False

                else:
                    if self._state.backtracking > 0:
                        raise BacktrackingFailed

                    mse = MismatchedSetException(None, self.input)
                    raise mse





                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 80, propertyName_StartIndex, success)

            pass
        return retval

    # $ANTLR end "propertyName"

    class literal_return(ParserRuleReturnScope):
        def __init__(self):
            super(JavaScriptParser.literal_return, self).__init__()

            self.tree = None




    # $ANTLR start "literal"
    # /home/buffer/antlr/JavaScript.g:376:1: literal : ( 'null' | 'true' | 'false' | StringLiteral | NumericLiteral );
    def literal(self, ):

        retval = self.literal_return()
        retval.start = self.input.LT(1)
        literal_StartIndex = self.input.index()
        root_0 = None

        set446 = None

        set446_tree = None

        success = False
        try:
            try:
                if self._state.backtracking > 0 and self.alreadyParsedRule(self.input, 81):
                    # for cached failed rules, alreadyParsedRule will raise an exception
                    success = True
                    return retval

                # /home/buffer/antlr/JavaScript.g:377:2: ( 'null' | 'true' | 'false' | StringLiteral | NumericLiteral )
                # /home/buffer/antlr/JavaScript.g:
                pass 
                root_0 = self._adaptor.nil()

                set446 = self.input.LT(1)
                if (StringLiteral <= self.input.LA(1) <= NumericLiteral) or (104 <= self.input.LA(1) <= 106):
                    self.input.consume()
                    if self._state.backtracking == 0:
                        self._adaptor.addChild(root_0, self._adaptor.createWithPayload(set446))
                    self._state.errorRecovery = False

                else:
                    if self._state.backtracking > 0:
                        raise BacktrackingFailed

                    mse = MismatchedSetException(None, self.input)
                    raise mse





                retval.stop = self.input.LT(-1)

                if self._state.backtracking == 0:

                    retval.tree = self._adaptor.rulePostProcessing(root_0)
                    self._adaptor.setTokenBoundaries(retval.tree, retval.start, retval.stop)


                success = True
            except RecognitionException, re:
                self.reportError(re)
                self.recover(self.input, re)
                retval.tree = self._adaptor.errorNode(self.input, retval.start, self.input.LT(-1), re)
        finally:
            if self._state.backtracking > 0:
                self.memoize(self.input, 81, literal_StartIndex, success)

            pass
        return retval

    # $ANTLR end "literal"

    # $ANTLR start "synpred5_JavaScript"
    def synpred5_JavaScript_fragment(self, ):
        # /home/buffer/antlr/JavaScript.g:25:4: ( functionDeclaration )
        # /home/buffer/antlr/JavaScript.g:25:4: functionDeclaration
        pass 
        self._state.following.append(self.FOLLOW_functionDeclaration_in_synpred5_JavaScript87)
        self.functionDeclaration()

        self._state.following.pop()


    # $ANTLR end "synpred5_JavaScript"



    # $ANTLR start "synpred9_JavaScript"
    def synpred9_JavaScript_fragment(self, ):
        # /home/buffer/antlr/JavaScript.g:35:15: ( LT )
        # /home/buffer/antlr/JavaScript.g:35:15: LT
        pass 
        self.match(self.input, LT, self.FOLLOW_LT_in_synpred9_JavaScript137)


    # $ANTLR end "synpred9_JavaScript"



    # $ANTLR start "synpred21_JavaScript"
    def synpred21_JavaScript_fragment(self, ):
        # /home/buffer/antlr/JavaScript.g:48:4: ( statementBlock )
        # /home/buffer/antlr/JavaScript.g:48:4: statementBlock
        pass 
        self._state.following.append(self.FOLLOW_statementBlock_in_synpred21_JavaScript231)
        self.statementBlock()

        self._state.following.pop()


    # $ANTLR end "synpred21_JavaScript"



    # $ANTLR start "synpred24_JavaScript"
    def synpred24_JavaScript_fragment(self, ):
        # /home/buffer/antlr/JavaScript.g:51:4: ( expressionStatement )
        # /home/buffer/antlr/JavaScript.g:51:4: expressionStatement
        pass 
        self._state.following.append(self.FOLLOW_expressionStatement_in_synpred24_JavaScript246)
        self.expressionStatement()

        self._state.following.pop()


    # $ANTLR end "synpred24_JavaScript"



    # $ANTLR start "synpred31_JavaScript"
    def synpred31_JavaScript_fragment(self, ):
        # /home/buffer/antlr/JavaScript.g:58:4: ( labelledStatement )
        # /home/buffer/antlr/JavaScript.g:58:4: labelledStatement
        pass 
        self._state.following.append(self.FOLLOW_labelledStatement_in_synpred31_JavaScript281)
        self.labelledStatement()

        self._state.following.pop()


    # $ANTLR end "synpred31_JavaScript"



    # $ANTLR start "synpred34_JavaScript"
    def synpred34_JavaScript_fragment(self, ):
        # /home/buffer/antlr/JavaScript.g:65:8: ( LT )
        # /home/buffer/antlr/JavaScript.g:65:8: LT
        pass 
        self.match(self.input, LT, self.FOLLOW_LT_in_synpred34_JavaScript310)


    # $ANTLR end "synpred34_JavaScript"



    # $ANTLR start "synpred47_JavaScript"
    def synpred47_JavaScript_fragment(self, ):
        # /home/buffer/antlr/JavaScript.g:85:15: ( LT )
        # /home/buffer/antlr/JavaScript.g:85:15: LT
        pass 
        self.match(self.input, LT, self.FOLLOW_LT_in_synpred47_JavaScript437)


    # $ANTLR end "synpred47_JavaScript"



    # $ANTLR start "synpred49_JavaScript"
    def synpred49_JavaScript_fragment(self, ):
        # /home/buffer/antlr/JavaScript.g:89:15: ( LT )
        # /home/buffer/antlr/JavaScript.g:89:15: LT
        pass 
        self.match(self.input, LT, self.FOLLOW_LT_in_synpred49_JavaScript456)


    # $ANTLR end "synpred49_JavaScript"



    # $ANTLR start "synpred60_JavaScript"
    def synpred60_JavaScript_fragment(self, ):
        # /home/buffer/antlr/JavaScript.g:109:59: ( ( LT )* 'else' ( LT )* statement )
        # /home/buffer/antlr/JavaScript.g:109:59: ( LT )* 'else' ( LT )* statement
        pass 
        # /home/buffer/antlr/JavaScript.g:109:61: ( LT )*
        while True: #loop239
            alt239 = 2
            LA239_0 = self.input.LA(1)

            if (LA239_0 == LT) :
                alt239 = 1


            if alt239 == 1:
                # /home/buffer/antlr/JavaScript.g:0:0: LT
                pass 
                self.match(self.input, LT, self.FOLLOW_LT_in_synpred60_JavaScript569)


            else:
                break #loop239
        self.match(self.input, 41, self.FOLLOW_41_in_synpred60_JavaScript573)
        # /home/buffer/antlr/JavaScript.g:109:73: ( LT )*
        while True: #loop240
            alt240 = 2
            LA240_0 = self.input.LA(1)

            if (LA240_0 == LT) :
                alt240 = 1


            if alt240 == 1:
                # /home/buffer/antlr/JavaScript.g:0:0: LT
                pass 
                self.match(self.input, LT, self.FOLLOW_LT_in_synpred60_JavaScript575)


            else:
                break #loop240
        self._state.following.append(self.FOLLOW_statement_in_synpred60_JavaScript579)
        self.statement()

        self._state.following.pop()


    # $ANTLR end "synpred60_JavaScript"



    # $ANTLR start "synpred63_JavaScript"
    def synpred63_JavaScript_fragment(self, ):
        # /home/buffer/antlr/JavaScript.g:115:4: ( forStatement )
        # /home/buffer/antlr/JavaScript.g:115:4: forStatement
        pass 
        self._state.following.append(self.FOLLOW_forStatement_in_synpred63_JavaScript603)
        self.forStatement()

        self._state.following.pop()


    # $ANTLR end "synpred63_JavaScript"



    # $ANTLR start "synpred118_JavaScript"
    def synpred118_JavaScript_fragment(self, ):
        # /home/buffer/antlr/JavaScript.g:174:36: ( LT )
        # /home/buffer/antlr/JavaScript.g:174:36: LT
        pass 
        self.match(self.input, LT, self.FOLLOW_LT_in_synpred118_JavaScript1084)


    # $ANTLR end "synpred118_JavaScript"



    # $ANTLR start "synpred121_JavaScript"
    def synpred121_JavaScript_fragment(self, ):
        # /home/buffer/antlr/JavaScript.g:178:23: ( LT )
        # /home/buffer/antlr/JavaScript.g:178:23: LT
        pass 
        self.match(self.input, LT, self.FOLLOW_LT_in_synpred121_JavaScript1109)


    # $ANTLR end "synpred121_JavaScript"



    # $ANTLR start "synpred140_JavaScript"
    def synpred140_JavaScript_fragment(self, ):
        # /home/buffer/antlr/JavaScript.g:207:4: ( conditionalExpression )
        # /home/buffer/antlr/JavaScript.g:207:4: conditionalExpression
        pass 
        self._state.following.append(self.FOLLOW_conditionalExpression_in_synpred140_JavaScript1301)
        self.conditionalExpression()

        self._state.following.pop()


    # $ANTLR end "synpred140_JavaScript"



    # $ANTLR start "synpred143_JavaScript"
    def synpred143_JavaScript_fragment(self, ):
        # /home/buffer/antlr/JavaScript.g:212:4: ( conditionalExpressionNoIn )
        # /home/buffer/antlr/JavaScript.g:212:4: conditionalExpressionNoIn
        pass 
        self._state.following.append(self.FOLLOW_conditionalExpressionNoIn_in_synpred143_JavaScript1330)
        self.conditionalExpressionNoIn()

        self._state.following.pop()


    # $ANTLR end "synpred143_JavaScript"



    # $ANTLR start "synpred146_JavaScript"
    def synpred146_JavaScript_fragment(self, ):
        # /home/buffer/antlr/JavaScript.g:217:4: ( callExpression )
        # /home/buffer/antlr/JavaScript.g:217:4: callExpression
        pass 
        self._state.following.append(self.FOLLOW_callExpression_in_synpred146_JavaScript1359)
        self.callExpression()

        self._state.following.pop()


    # $ANTLR end "synpred146_JavaScript"



    # $ANTLR start "synpred147_JavaScript"
    def synpred147_JavaScript_fragment(self, ):
        # /home/buffer/antlr/JavaScript.g:222:4: ( memberExpression )
        # /home/buffer/antlr/JavaScript.g:222:4: memberExpression
        pass 
        self._state.following.append(self.FOLLOW_memberExpression_in_synpred147_JavaScript1376)
        self.memberExpression()

        self._state.following.pop()


    # $ANTLR end "synpred147_JavaScript"



    # $ANTLR start "synpred154_JavaScript"
    def synpred154_JavaScript_fragment(self, ):
        # /home/buffer/antlr/JavaScript.g:227:91: ( ( LT )* memberExpressionSuffix )
        # /home/buffer/antlr/JavaScript.g:227:91: ( LT )* memberExpressionSuffix
        pass 
        # /home/buffer/antlr/JavaScript.g:227:93: ( LT )*
        while True: #loop254
            alt254 = 2
            LA254_0 = self.input.LA(1)

            if (LA254_0 == LT) :
                alt254 = 1


            if alt254 == 1:
                # /home/buffer/antlr/JavaScript.g:0:0: LT
                pass 
                self.match(self.input, LT, self.FOLLOW_LT_in_synpred154_JavaScript1424)


            else:
                break #loop254
        self._state.following.append(self.FOLLOW_memberExpressionSuffix_in_synpred154_JavaScript1428)
        self.memberExpressionSuffix()

        self._state.following.pop()


    # $ANTLR end "synpred154_JavaScript"



    # $ANTLR start "synpred158_JavaScript"
    def synpred158_JavaScript_fragment(self, ):
        # /home/buffer/antlr/JavaScript.g:236:37: ( ( LT )* callExpressionSuffix )
        # /home/buffer/antlr/JavaScript.g:236:37: ( LT )* callExpressionSuffix
        pass 
        # /home/buffer/antlr/JavaScript.g:236:39: ( LT )*
        while True: #loop255
            alt255 = 2
            LA255_0 = self.input.LA(1)

            if (LA255_0 == LT) :
                alt255 = 1


            if alt255 == 1:
                # /home/buffer/antlr/JavaScript.g:0:0: LT
                pass 
                self.match(self.input, LT, self.FOLLOW_LT_in_synpred158_JavaScript1467)


            else:
                break #loop255
        self._state.following.append(self.FOLLOW_callExpressionSuffix_in_synpred158_JavaScript1471)
        self.callExpressionSuffix()

        self._state.following.pop()


    # $ANTLR end "synpred158_JavaScript"



    # $ANTLR start "synpred256_JavaScript"
    def synpred256_JavaScript_fragment(self, ):
        # /home/buffer/antlr/JavaScript.g:330:30: ( ( LT )* ( '+' | '-' ) ( LT )* multiplicativeExpression )
        # /home/buffer/antlr/JavaScript.g:330:30: ( LT )* ( '+' | '-' ) ( LT )* multiplicativeExpression
        pass 
        # /home/buffer/antlr/JavaScript.g:330:32: ( LT )*
        while True: #loop300
            alt300 = 2
            LA300_0 = self.input.LA(1)

            if (LA300_0 == LT) :
                alt300 = 1


            if alt300 == 1:
                # /home/buffer/antlr/JavaScript.g:0:0: LT
                pass 
                self.match(self.input, LT, self.FOLLOW_LT_in_synpred256_JavaScript2204)


            else:
                break #loop300
        if (91 <= self.input.LA(1) <= 92):
            self.input.consume()
            self._state.errorRecovery = False

        else:
            if self._state.backtracking > 0:
                raise BacktrackingFailed

            mse = MismatchedSetException(None, self.input)
            raise mse


        # /home/buffer/antlr/JavaScript.g:330:49: ( LT )*
        while True: #loop301
            alt301 = 2
            LA301_0 = self.input.LA(1)

            if (LA301_0 == LT) :
                alt301 = 1


            if alt301 == 1:
                # /home/buffer/antlr/JavaScript.g:0:0: LT
                pass 
                self.match(self.input, LT, self.FOLLOW_LT_in_synpred256_JavaScript2216)


            else:
                break #loop301
        self._state.following.append(self.FOLLOW_multiplicativeExpression_in_synpred256_JavaScript2220)
        self.multiplicativeExpression()

        self._state.following.pop()


    # $ANTLR end "synpred256_JavaScript"



    # $ANTLR start "synpred280_JavaScript"
    def synpred280_JavaScript_fragment(self, ):
        # /home/buffer/antlr/JavaScript.g:357:8: ( LT )
        # /home/buffer/antlr/JavaScript.g:357:8: LT
        pass 
        self.match(self.input, LT, self.FOLLOW_LT_in_synpred280_JavaScript2394)


    # $ANTLR end "synpred280_JavaScript"




    # Delegated rules

    def synpred60_JavaScript(self):
        self._state.backtracking += 1
        start = self.input.mark()
        try:
            self.synpred60_JavaScript_fragment()
        except BacktrackingFailed:
            success = False
        else:
            success = True
        self.input.rewind(start)
        self._state.backtracking -= 1
        return success

    def synpred121_JavaScript(self):
        self._state.backtracking += 1
        start = self.input.mark()
        try:
            self.synpred121_JavaScript_fragment()
        except BacktrackingFailed:
            success = False
        else:
            success = True
        self.input.rewind(start)
        self._state.backtracking -= 1
        return success

    def synpred146_JavaScript(self):
        self._state.backtracking += 1
        start = self.input.mark()
        try:
            self.synpred146_JavaScript_fragment()
        except BacktrackingFailed:
            success = False
        else:
            success = True
        self.input.rewind(start)
        self._state.backtracking -= 1
        return success

    def synpred154_JavaScript(self):
        self._state.backtracking += 1
        start = self.input.mark()
        try:
            self.synpred154_JavaScript_fragment()
        except BacktrackingFailed:
            success = False
        else:
            success = True
        self.input.rewind(start)
        self._state.backtracking -= 1
        return success

    def synpred34_JavaScript(self):
        self._state.backtracking += 1
        start = self.input.mark()
        try:
            self.synpred34_JavaScript_fragment()
        except BacktrackingFailed:
            success = False
        else:
            success = True
        self.input.rewind(start)
        self._state.backtracking -= 1
        return success

    def synpred147_JavaScript(self):
        self._state.backtracking += 1
        start = self.input.mark()
        try:
            self.synpred147_JavaScript_fragment()
        except BacktrackingFailed:
            success = False
        else:
            success = True
        self.input.rewind(start)
        self._state.backtracking -= 1
        return success

    def synpred63_JavaScript(self):
        self._state.backtracking += 1
        start = self.input.mark()
        try:
            self.synpred63_JavaScript_fragment()
        except BacktrackingFailed:
            success = False
        else:
            success = True
        self.input.rewind(start)
        self._state.backtracking -= 1
        return success

    def synpred47_JavaScript(self):
        self._state.backtracking += 1
        start = self.input.mark()
        try:
            self.synpred47_JavaScript_fragment()
        except BacktrackingFailed:
            success = False
        else:
            success = True
        self.input.rewind(start)
        self._state.backtracking -= 1
        return success

    def synpred256_JavaScript(self):
        self._state.backtracking += 1
        start = self.input.mark()
        try:
            self.synpred256_JavaScript_fragment()
        except BacktrackingFailed:
            success = False
        else:
            success = True
        self.input.rewind(start)
        self._state.backtracking -= 1
        return success

    def synpred280_JavaScript(self):
        self._state.backtracking += 1
        start = self.input.mark()
        try:
            self.synpred280_JavaScript_fragment()
        except BacktrackingFailed:
            success = False
        else:
            success = True
        self.input.rewind(start)
        self._state.backtracking -= 1
        return success

    def synpred118_JavaScript(self):
        self._state.backtracking += 1
        start = self.input.mark()
        try:
            self.synpred118_JavaScript_fragment()
        except BacktrackingFailed:
            success = False
        else:
            success = True
        self.input.rewind(start)
        self._state.backtracking -= 1
        return success

    def synpred158_JavaScript(self):
        self._state.backtracking += 1
        start = self.input.mark()
        try:
            self.synpred158_JavaScript_fragment()
        except BacktrackingFailed:
            success = False
        else:
            success = True
        self.input.rewind(start)
        self._state.backtracking -= 1
        return success

    def synpred9_JavaScript(self):
        self._state.backtracking += 1
        start = self.input.mark()
        try:
            self.synpred9_JavaScript_fragment()
        except BacktrackingFailed:
            success = False
        else:
            success = True
        self.input.rewind(start)
        self._state.backtracking -= 1
        return success

    def synpred21_JavaScript(self):
        self._state.backtracking += 1
        start = self.input.mark()
        try:
            self.synpred21_JavaScript_fragment()
        except BacktrackingFailed:
            success = False
        else:
            success = True
        self.input.rewind(start)
        self._state.backtracking -= 1
        return success

    def synpred31_JavaScript(self):
        self._state.backtracking += 1
        start = self.input.mark()
        try:
            self.synpred31_JavaScript_fragment()
        except BacktrackingFailed:
            success = False
        else:
            success = True
        self.input.rewind(start)
        self._state.backtracking -= 1
        return success

    def synpred49_JavaScript(self):
        self._state.backtracking += 1
        start = self.input.mark()
        try:
            self.synpred49_JavaScript_fragment()
        except BacktrackingFailed:
            success = False
        else:
            success = True
        self.input.rewind(start)
        self._state.backtracking -= 1
        return success

    def synpred24_JavaScript(self):
        self._state.backtracking += 1
        start = self.input.mark()
        try:
            self.synpred24_JavaScript_fragment()
        except BacktrackingFailed:
            success = False
        else:
            success = True
        self.input.rewind(start)
        self._state.backtracking -= 1
        return success

    def synpred143_JavaScript(self):
        self._state.backtracking += 1
        start = self.input.mark()
        try:
            self.synpred143_JavaScript_fragment()
        except BacktrackingFailed:
            success = False
        else:
            success = True
        self.input.rewind(start)
        self._state.backtracking -= 1
        return success

    def synpred140_JavaScript(self):
        self._state.backtracking += 1
        start = self.input.mark()
        try:
            self.synpred140_JavaScript_fragment()
        except BacktrackingFailed:
            success = False
        else:
            success = True
        self.input.rewind(start)
        self._state.backtracking -= 1
        return success

    def synpred5_JavaScript(self):
        self._state.backtracking += 1
        start = self.input.mark()
        try:
            self.synpred5_JavaScript_fragment()
        except BacktrackingFailed:
            success = False
        else:
            success = True
        self.input.rewind(start)
        self._state.backtracking -= 1
        return success



    # lookup tables for DFA #4

    DFA4_eot = DFA.unpack(
        u"\4\uffff"
        )

    DFA4_eof = DFA.unpack(
        u"\2\2\2\uffff"
        )

    DFA4_min = DFA.unpack(
        u"\2\4\2\uffff"
        )

    DFA4_max = DFA.unpack(
        u"\2\152\2\uffff"
        )

    DFA4_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1"
        )

    DFA4_special = DFA.unpack(
        u"\4\uffff"
        )

            
    DFA4_transition = [
        DFA.unpack(u"\1\1\3\3\27\uffff\2\3\2\uffff\1\3\1\2\2\3\1\uffff\1"
        u"\3\1\uffff\3\3\1\uffff\4\3\1\uffff\1\3\2\uffff\2\3\2\uffff\2\3"
        u"\37\uffff\2\3\3\uffff\13\3"),
        DFA.unpack(u"\1\1\3\3\27\uffff\2\3\2\uffff\1\3\1\2\2\3\1\uffff\1"
        u"\3\1\uffff\3\3\1\uffff\4\3\1\uffff\1\3\2\uffff\2\3\2\uffff\2\3"
        u"\37\uffff\2\3\3\uffff\13\3"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #4

    class DFA4(DFA):
        pass


    # lookup tables for DFA #5

    DFA5_eot = DFA.unpack(
        u"\30\uffff"
        )

    DFA5_eof = DFA.unpack(
        u"\30\uffff"
        )

    DFA5_min = DFA.unpack(
        u"\1\5\1\0\26\uffff"
        )

    DFA5_max = DFA.unpack(
        u"\1\152\1\0\26\uffff"
        )

    DFA5_accept = DFA.unpack(
        u"\2\uffff\1\2\24\uffff\1\1"
        )

    DFA5_special = DFA.unpack(
        u"\1\uffff\1\0\26\uffff"
        )

            
    DFA5_transition = [
        DFA.unpack(u"\3\2\27\uffff\1\1\1\2\2\uffff\1\2\1\uffff\2\2\1\uffff"
        u"\1\2\1\uffff\3\2\1\uffff\4\2\1\uffff\1\2\2\uffff\2\2\2\uffff\2"
        u"\2\37\uffff\2\2\3\uffff\13\2"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #5

    class DFA5(DFA):
        pass


        def specialStateTransition(self_, s, input):
            # convince pylint that my self_ magic is ok ;)
            # pylint: disable-msg=E0213

            # pretend we are a member of the recognizer
            # thus semantic predicates can be evaluated
            self = self_.recognizer

            _s = s

            if s == 0: 
                LA5_1 = input.LA(1)

                 
                index5_1 = input.index()
                input.rewind()
                s = -1
                if (self.synpred5_JavaScript()):
                    s = 23

                elif (True):
                    s = 2

                 
                input.seek(index5_1)
                if s >= 0:
                    return s

            if self._state.backtracking >0:
                raise BacktrackingFailed
            nvae = NoViableAltException(self_.getDescription(), 5, _s, input)
            self_.error(nvae)
            raise nvae
    # lookup tables for DFA #17

    DFA17_eot = DFA.unpack(
        u"\4\uffff"
        )

    DFA17_eof = DFA.unpack(
        u"\4\uffff"
        )

    DFA17_min = DFA.unpack(
        u"\2\4\2\uffff"
        )

    DFA17_max = DFA.unpack(
        u"\2\42\2\uffff"
        )

    DFA17_accept = DFA.unpack(
        u"\2\uffff\1\1\1\2"
        )

    DFA17_special = DFA.unpack(
        u"\4\uffff"
        )

            
    DFA17_transition = [
        DFA.unpack(u"\1\1\1\2\34\uffff\1\3"),
        DFA.unpack(u"\1\1\1\2\34\uffff\1\3"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #17

    class DFA17(DFA):
        pass


    # lookup tables for DFA #16

    DFA16_eot = DFA.unpack(
        u"\4\uffff"
        )

    DFA16_eof = DFA.unpack(
        u"\4\uffff"
        )

    DFA16_min = DFA.unpack(
        u"\2\4\2\uffff"
        )

    DFA16_max = DFA.unpack(
        u"\2\42\2\uffff"
        )

    DFA16_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1"
        )

    DFA16_special = DFA.unpack(
        u"\4\uffff"
        )

            
    DFA16_transition = [
        DFA.unpack(u"\1\1\34\uffff\1\3\1\2"),
        DFA.unpack(u"\1\1\34\uffff\1\3\1\2"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #16

    class DFA16(DFA):
        pass


    # lookup tables for DFA #21

    DFA21_eot = DFA.unpack(
        u"\31\uffff"
        )

    DFA21_eof = DFA.unpack(
        u"\31\uffff"
        )

    DFA21_min = DFA.unpack(
        u"\1\5\1\0\3\uffff\1\0\23\uffff"
        )

    DFA21_max = DFA.unpack(
        u"\1\152\1\0\3\uffff\1\0\23\uffff"
        )

    DFA21_accept = DFA.unpack(
        u"\2\uffff\1\2\1\3\1\4\7\uffff\1\5\1\6\2\uffff\1\7\1\10\1\11\1\12"
        u"\1\14\1\15\1\16\1\1\1\13"
        )

    DFA21_special = DFA.unpack(
        u"\1\uffff\1\0\3\uffff\1\1\23\uffff"
        )

            
    DFA21_transition = [
        DFA.unpack(u"\1\5\2\4\27\uffff\2\4\2\uffff\1\1\1\uffff\1\2\1\3\1"
        u"\uffff\1\14\1\uffff\3\15\1\uffff\1\20\1\21\1\22\1\23\1\uffff\1"
        u"\24\2\uffff\1\25\1\26\2\uffff\2\4\37\uffff\2\4\3\uffff\13\4"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #21

    class DFA21(DFA):
        pass


        def specialStateTransition(self_, s, input):
            # convince pylint that my self_ magic is ok ;)
            # pylint: disable-msg=E0213

            # pretend we are a member of the recognizer
            # thus semantic predicates can be evaluated
            self = self_.recognizer

            _s = s

            if s == 0: 
                LA21_1 = input.LA(1)

                 
                index21_1 = input.index()
                input.rewind()
                s = -1
                if (self.synpred21_JavaScript()):
                    s = 23

                elif (self.synpred24_JavaScript()):
                    s = 4

                 
                input.seek(index21_1)
                if s >= 0:
                    return s
            elif s == 1: 
                LA21_5 = input.LA(1)

                 
                index21_5 = input.index()
                input.rewind()
                s = -1
                if (self.synpred24_JavaScript()):
                    s = 4

                elif (self.synpred31_JavaScript()):
                    s = 24

                 
                input.seek(index21_5)
                if s >= 0:
                    return s

            if self._state.backtracking >0:
                raise BacktrackingFailed
            nvae = NoViableAltException(self_.getDescription(), 21, _s, input)
            self_.error(nvae)
            raise nvae
    # lookup tables for DFA #26

    DFA26_eot = DFA.unpack(
        u"\4\uffff"
        )

    DFA26_eof = DFA.unpack(
        u"\1\2\3\uffff"
        )

    DFA26_min = DFA.unpack(
        u"\2\4\2\uffff"
        )

    DFA26_max = DFA.unpack(
        u"\2\152\2\uffff"
        )

    DFA26_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1"
        )

    DFA26_special = DFA.unpack(
        u"\4\uffff"
        )

            
    DFA26_transition = [
        DFA.unpack(u"\1\1\3\3\27\uffff\2\3\2\uffff\1\3\1\2\2\3\1\uffff\1"
        u"\3\1\uffff\3\3\1\uffff\4\3\1\uffff\1\3\2\2\2\3\2\uffff\2\3\37\uffff"
        u"\2\3\3\uffff\13\3"),
        DFA.unpack(u"\1\1\3\3\27\uffff\2\3\2\uffff\1\3\1\2\2\3\1\uffff\1"
        u"\3\1\uffff\3\3\1\uffff\4\3\1\uffff\1\3\2\2\2\3\2\uffff\2\3\37\uffff"
        u"\2\3\3\uffff\13\3"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #26

    class DFA26(DFA):
        pass


    # lookup tables for DFA #30

    DFA30_eot = DFA.unpack(
        u"\5\uffff"
        )

    DFA30_eof = DFA.unpack(
        u"\1\uffff\1\2\2\uffff\1\2"
        )

    DFA30_min = DFA.unpack(
        u"\2\4\2\uffff\1\4"
        )

    DFA30_max = DFA.unpack(
        u"\1\46\1\152\2\uffff\1\152"
        )

    DFA30_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1\1\uffff"
        )

    DFA30_special = DFA.unpack(
        u"\5\uffff"
        )

            
    DFA30_transition = [
        DFA.unpack(u"\1\1\34\uffff\1\3\4\uffff\1\2"),
        DFA.unpack(u"\1\4\3\2\27\uffff\2\2\1\3\1\uffff\4\2\1\uffff\5\2\1"
        u"\uffff\4\2\1\uffff\5\2\2\uffff\2\2\37\uffff\2\2\3\uffff\13\2"),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u"\1\4\3\2\27\uffff\2\2\1\3\1\uffff\4\2\1\uffff\5\2\1"
        u"\uffff\4\2\1\uffff\5\2\2\uffff\2\2\37\uffff\2\2\3\uffff\13\2")
    ]

    # class definition for DFA #30

    class DFA30(DFA):
        pass


    # lookup tables for DFA #33

    DFA33_eot = DFA.unpack(
        u"\4\uffff"
        )

    DFA33_eof = DFA.unpack(
        u"\1\2\3\uffff"
        )

    DFA33_min = DFA.unpack(
        u"\2\4\2\uffff"
        )

    DFA33_max = DFA.unpack(
        u"\2\46\2\uffff"
        )

    DFA33_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1"
        )

    DFA33_special = DFA.unpack(
        u"\4\uffff"
        )

            
    DFA33_transition = [
        DFA.unpack(u"\1\1\34\uffff\1\3\4\uffff\1\2"),
        DFA.unpack(u"\1\1\34\uffff\1\3\4\uffff\1\2"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #33

    class DFA33(DFA):
        pass


    # lookup tables for DFA #57

    DFA57_eot = DFA.unpack(
        u"\4\uffff"
        )

    DFA57_eof = DFA.unpack(
        u"\4\uffff"
        )

    DFA57_min = DFA.unpack(
        u"\2\4\2\uffff"
        )

    DFA57_max = DFA.unpack(
        u"\2\152\2\uffff"
        )

    DFA57_accept = DFA.unpack(
        u"\2\uffff\1\1\1\2"
        )

    DFA57_special = DFA.unpack(
        u"\4\uffff"
        )

            
    DFA57_transition = [
        DFA.unpack(u"\1\1\3\2\27\uffff\2\2\2\uffff\1\2\1\uffff\1\2\1\3\23"
        u"\uffff\2\2\37\uffff\2\2\3\uffff\13\2"),
        DFA.unpack(u"\1\1\3\2\27\uffff\2\2\2\uffff\1\2\1\uffff\1\2\1\3\23"
        u"\uffff\2\2\37\uffff\2\2\3\uffff\13\2"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #57

    class DFA57(DFA):
        pass


    # lookup tables for DFA #60

    DFA60_eot = DFA.unpack(
        u"\4\uffff"
        )

    DFA60_eof = DFA.unpack(
        u"\4\uffff"
        )

    DFA60_min = DFA.unpack(
        u"\2\4\2\uffff"
        )

    DFA60_max = DFA.unpack(
        u"\2\152\2\uffff"
        )

    DFA60_accept = DFA.unpack(
        u"\2\uffff\1\1\1\2"
        )

    DFA60_special = DFA.unpack(
        u"\4\uffff"
        )

            
    DFA60_transition = [
        DFA.unpack(u"\1\1\3\2\27\uffff\2\2\2\uffff\1\2\2\uffff\1\3\23\uffff"
        u"\2\2\37\uffff\2\2\3\uffff\13\2"),
        DFA.unpack(u"\1\1\3\2\27\uffff\2\2\2\uffff\1\2\2\uffff\1\3\23\uffff"
        u"\2\2\37\uffff\2\2\3\uffff\13\2"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #60

    class DFA60(DFA):
        pass


    # lookup tables for DFA #63

    DFA63_eot = DFA.unpack(
        u"\4\uffff"
        )

    DFA63_eof = DFA.unpack(
        u"\4\uffff"
        )

    DFA63_min = DFA.unpack(
        u"\2\4\2\uffff"
        )

    DFA63_max = DFA.unpack(
        u"\2\152\2\uffff"
        )

    DFA63_accept = DFA.unpack(
        u"\2\uffff\1\1\1\2"
        )

    DFA63_special = DFA.unpack(
        u"\4\uffff"
        )

            
    DFA63_transition = [
        DFA.unpack(u"\1\1\3\2\27\uffff\2\2\1\uffff\1\3\1\2\26\uffff\2\2\37"
        u"\uffff\2\2\3\uffff\13\2"),
        DFA.unpack(u"\1\1\3\2\27\uffff\2\2\1\uffff\1\3\1\2\26\uffff\2\2"
        u"\37\uffff\2\2\3\uffff\13\2"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #63

    class DFA63(DFA):
        pass


    # lookup tables for DFA #90

    DFA90_eot = DFA.unpack(
        u"\4\uffff"
        )

    DFA90_eof = DFA.unpack(
        u"\4\uffff"
        )

    DFA90_min = DFA.unpack(
        u"\2\4\2\uffff"
        )

    DFA90_max = DFA.unpack(
        u"\2\65\2\uffff"
        )

    DFA90_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1"
        )

    DFA90_special = DFA.unpack(
        u"\4\uffff"
        )

            
    DFA90_transition = [
        DFA.unpack(u"\1\1\37\uffff\1\2\17\uffff\1\3\1\2"),
        DFA.unpack(u"\1\1\37\uffff\1\2\17\uffff\1\3\1\2"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #90

    class DFA90(DFA):
        pass


    # lookup tables for DFA #94

    DFA94_eot = DFA.unpack(
        u"\4\uffff"
        )

    DFA94_eof = DFA.unpack(
        u"\4\uffff"
        )

    DFA94_min = DFA.unpack(
        u"\2\4\2\uffff"
        )

    DFA94_max = DFA.unpack(
        u"\2\65\2\uffff"
        )

    DFA94_accept = DFA.unpack(
        u"\2\uffff\1\1\1\2"
        )

    DFA94_special = DFA.unpack(
        u"\4\uffff"
        )

            
    DFA94_transition = [
        DFA.unpack(u"\1\1\37\uffff\1\3\20\uffff\1\2"),
        DFA.unpack(u"\1\1\37\uffff\1\3\20\uffff\1\2"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #94

    class DFA94(DFA):
        pass


    # lookup tables for DFA #93

    DFA93_eot = DFA.unpack(
        u"\4\uffff"
        )

    DFA93_eof = DFA.unpack(
        u"\4\uffff"
        )

    DFA93_min = DFA.unpack(
        u"\2\4\2\uffff"
        )

    DFA93_max = DFA.unpack(
        u"\2\64\2\uffff"
        )

    DFA93_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1"
        )

    DFA93_special = DFA.unpack(
        u"\4\uffff"
        )

            
    DFA93_transition = [
        DFA.unpack(u"\1\1\37\uffff\1\2\17\uffff\1\3"),
        DFA.unpack(u"\1\1\37\uffff\1\2\17\uffff\1\3"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #93

    class DFA93(DFA):
        pass


    # lookup tables for DFA #106

    DFA106_eot = DFA.unpack(
        u"\4\uffff"
        )

    DFA106_eof = DFA.unpack(
        u"\2\3\2\uffff"
        )

    DFA106_min = DFA.unpack(
        u"\2\4\2\uffff"
        )

    DFA106_max = DFA.unpack(
        u"\2\152\2\uffff"
        )

    DFA106_accept = DFA.unpack(
        u"\2\uffff\1\1\1\2"
        )

    DFA106_special = DFA.unpack(
        u"\4\uffff"
        )

            
    DFA106_transition = [
        DFA.unpack(u"\1\1\3\3\27\uffff\2\3\2\uffff\4\3\1\uffff\5\3\1\uffff"
        u"\4\3\1\uffff\5\3\1\uffff\1\2\2\3\37\uffff\2\3\3\uffff\13\3"),
        DFA.unpack(u"\1\1\3\3\27\uffff\2\3\2\uffff\4\3\1\uffff\5\3\1\uffff"
        u"\4\3\1\uffff\5\3\1\uffff\1\2\2\3\37\uffff\2\3\3\uffff\13\3"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #106

    class DFA106(DFA):
        pass


    # lookup tables for DFA #115

    DFA115_eot = DFA.unpack(
        u"\5\uffff"
        )

    DFA115_eof = DFA.unpack(
        u"\2\2\2\uffff\1\2"
        )

    DFA115_min = DFA.unpack(
        u"\2\4\2\uffff\1\4"
        )

    DFA115_max = DFA.unpack(
        u"\1\74\1\152\2\uffff\1\152"
        )

    DFA115_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1\1\uffff"
        )

    DFA115_special = DFA.unpack(
        u"\5\uffff"
        )

            
    DFA115_transition = [
        DFA.unpack(u"\1\1\34\uffff\1\3\1\2\3\uffff\1\2\13\uffff\1\2\11\uffff"
        u"\1\2"),
        DFA.unpack(u"\1\4\3\2\27\uffff\2\2\1\3\5\2\1\uffff\5\2\1\uffff\12"
        u"\2\2\uffff\3\2\36\uffff\2\2\3\uffff\13\2"),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u"\1\4\3\2\27\uffff\2\2\1\3\5\2\1\uffff\5\2\1\uffff\12"
        u"\2\2\uffff\3\2\36\uffff\2\2\3\uffff\13\2")
    ]

    # class definition for DFA #115

    class DFA115(DFA):
        pass


    # lookup tables for DFA #118

    DFA118_eot = DFA.unpack(
        u"\4\uffff"
        )

    DFA118_eof = DFA.unpack(
        u"\1\2\3\uffff"
        )

    DFA118_min = DFA.unpack(
        u"\2\4\2\uffff"
        )

    DFA118_max = DFA.unpack(
        u"\2\46\2\uffff"
        )

    DFA118_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1"
        )

    DFA118_special = DFA.unpack(
        u"\4\uffff"
        )

            
    DFA118_transition = [
        DFA.unpack(u"\1\1\34\uffff\1\3\4\uffff\1\2"),
        DFA.unpack(u"\1\1\34\uffff\1\3\4\uffff\1\2"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #118

    class DFA118(DFA):
        pass


    # lookup tables for DFA #121

    DFA121_eot = DFA.unpack(
        u"\13\uffff"
        )

    DFA121_eof = DFA.unpack(
        u"\13\uffff"
        )

    DFA121_min = DFA.unpack(
        u"\1\5\10\0\2\uffff"
        )

    DFA121_max = DFA.unpack(
        u"\1\152\10\0\2\uffff"
        )

    DFA121_accept = DFA.unpack(
        u"\11\uffff\1\1\1\2"
        )

    DFA121_special = DFA.unpack(
        u"\1\uffff\1\0\1\1\1\2\1\3\1\4\1\5\1\6\1\7\2\uffff"
        )

            
    DFA121_transition = [
        DFA.unpack(u"\1\2\2\3\27\uffff\1\7\1\6\2\uffff\1\5\26\uffff\1\10"
        u"\1\4\37\uffff\2\11\3\uffff\7\11\1\1\3\3"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #121

    class DFA121(DFA):
        pass


        def specialStateTransition(self_, s, input):
            # convince pylint that my self_ magic is ok ;)
            # pylint: disable-msg=E0213

            # pretend we are a member of the recognizer
            # thus semantic predicates can be evaluated
            self = self_.recognizer

            _s = s

            if s == 0: 
                LA121_1 = input.LA(1)

                 
                index121_1 = input.index()
                input.rewind()
                s = -1
                if (self.synpred140_JavaScript()):
                    s = 9

                elif (True):
                    s = 10

                 
                input.seek(index121_1)
                if s >= 0:
                    return s
            elif s == 1: 
                LA121_2 = input.LA(1)

                 
                index121_2 = input.index()
                input.rewind()
                s = -1
                if (self.synpred140_JavaScript()):
                    s = 9

                elif (True):
                    s = 10

                 
                input.seek(index121_2)
                if s >= 0:
                    return s
            elif s == 2: 
                LA121_3 = input.LA(1)

                 
                index121_3 = input.index()
                input.rewind()
                s = -1
                if (self.synpred140_JavaScript()):
                    s = 9

                elif (True):
                    s = 10

                 
                input.seek(index121_3)
                if s >= 0:
                    return s
            elif s == 3: 
                LA121_4 = input.LA(1)

                 
                index121_4 = input.index()
                input.rewind()
                s = -1
                if (self.synpred140_JavaScript()):
                    s = 9

                elif (True):
                    s = 10

                 
                input.seek(index121_4)
                if s >= 0:
                    return s
            elif s == 4: 
                LA121_5 = input.LA(1)

                 
                index121_5 = input.index()
                input.rewind()
                s = -1
                if (self.synpred140_JavaScript()):
                    s = 9

                elif (True):
                    s = 10

                 
                input.seek(index121_5)
                if s >= 0:
                    return s
            elif s == 5: 
                LA121_6 = input.LA(1)

                 
                index121_6 = input.index()
                input.rewind()
                s = -1
                if (self.synpred140_JavaScript()):
                    s = 9

                elif (True):
                    s = 10

                 
                input.seek(index121_6)
                if s >= 0:
                    return s
            elif s == 6: 
                LA121_7 = input.LA(1)

                 
                index121_7 = input.index()
                input.rewind()
                s = -1
                if (self.synpred140_JavaScript()):
                    s = 9

                elif (True):
                    s = 10

                 
                input.seek(index121_7)
                if s >= 0:
                    return s
            elif s == 7: 
                LA121_8 = input.LA(1)

                 
                index121_8 = input.index()
                input.rewind()
                s = -1
                if (self.synpred140_JavaScript()):
                    s = 9

                elif (True):
                    s = 10

                 
                input.seek(index121_8)
                if s >= 0:
                    return s

            if self._state.backtracking >0:
                raise BacktrackingFailed
            nvae = NoViableAltException(self_.getDescription(), 121, _s, input)
            self_.error(nvae)
            raise nvae
    # lookup tables for DFA #124

    DFA124_eot = DFA.unpack(
        u"\13\uffff"
        )

    DFA124_eof = DFA.unpack(
        u"\13\uffff"
        )

    DFA124_min = DFA.unpack(
        u"\1\5\10\0\2\uffff"
        )

    DFA124_max = DFA.unpack(
        u"\1\152\10\0\2\uffff"
        )

    DFA124_accept = DFA.unpack(
        u"\11\uffff\1\1\1\2"
        )

    DFA124_special = DFA.unpack(
        u"\1\uffff\1\0\1\1\1\2\1\3\1\4\1\5\1\6\1\7\2\uffff"
        )

            
    DFA124_transition = [
        DFA.unpack(u"\1\2\2\3\27\uffff\1\7\1\6\2\uffff\1\5\26\uffff\1\10"
        u"\1\4\37\uffff\2\11\3\uffff\7\11\1\1\3\3"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #124

    class DFA124(DFA):
        pass


        def specialStateTransition(self_, s, input):
            # convince pylint that my self_ magic is ok ;)
            # pylint: disable-msg=E0213

            # pretend we are a member of the recognizer
            # thus semantic predicates can be evaluated
            self = self_.recognizer

            _s = s

            if s == 0: 
                LA124_1 = input.LA(1)

                 
                index124_1 = input.index()
                input.rewind()
                s = -1
                if (self.synpred143_JavaScript()):
                    s = 9

                elif (True):
                    s = 10

                 
                input.seek(index124_1)
                if s >= 0:
                    return s
            elif s == 1: 
                LA124_2 = input.LA(1)

                 
                index124_2 = input.index()
                input.rewind()
                s = -1
                if (self.synpred143_JavaScript()):
                    s = 9

                elif (True):
                    s = 10

                 
                input.seek(index124_2)
                if s >= 0:
                    return s
            elif s == 2: 
                LA124_3 = input.LA(1)

                 
                index124_3 = input.index()
                input.rewind()
                s = -1
                if (self.synpred143_JavaScript()):
                    s = 9

                elif (True):
                    s = 10

                 
                input.seek(index124_3)
                if s >= 0:
                    return s
            elif s == 3: 
                LA124_4 = input.LA(1)

                 
                index124_4 = input.index()
                input.rewind()
                s = -1
                if (self.synpred143_JavaScript()):
                    s = 9

                elif (True):
                    s = 10

                 
                input.seek(index124_4)
                if s >= 0:
                    return s
            elif s == 4: 
                LA124_5 = input.LA(1)

                 
                index124_5 = input.index()
                input.rewind()
                s = -1
                if (self.synpred143_JavaScript()):
                    s = 9

                elif (True):
                    s = 10

                 
                input.seek(index124_5)
                if s >= 0:
                    return s
            elif s == 5: 
                LA124_6 = input.LA(1)

                 
                index124_6 = input.index()
                input.rewind()
                s = -1
                if (self.synpred143_JavaScript()):
                    s = 9

                elif (True):
                    s = 10

                 
                input.seek(index124_6)
                if s >= 0:
                    return s
            elif s == 6: 
                LA124_7 = input.LA(1)

                 
                index124_7 = input.index()
                input.rewind()
                s = -1
                if (self.synpred143_JavaScript()):
                    s = 9

                elif (True):
                    s = 10

                 
                input.seek(index124_7)
                if s >= 0:
                    return s
            elif s == 7: 
                LA124_8 = input.LA(1)

                 
                index124_8 = input.index()
                input.rewind()
                s = -1
                if (self.synpred143_JavaScript()):
                    s = 9

                elif (True):
                    s = 10

                 
                input.seek(index124_8)
                if s >= 0:
                    return s

            if self._state.backtracking >0:
                raise BacktrackingFailed
            nvae = NoViableAltException(self_.getDescription(), 124, _s, input)
            self_.error(nvae)
            raise nvae
    # lookup tables for DFA #125

    DFA125_eot = DFA.unpack(
        u"\13\uffff"
        )

    DFA125_eof = DFA.unpack(
        u"\13\uffff"
        )

    DFA125_min = DFA.unpack(
        u"\1\5\10\0\2\uffff"
        )

    DFA125_max = DFA.unpack(
        u"\1\152\10\0\2\uffff"
        )

    DFA125_accept = DFA.unpack(
        u"\11\uffff\1\1\1\2"
        )

    DFA125_special = DFA.unpack(
        u"\1\uffff\1\0\1\1\1\2\1\3\1\4\1\5\1\6\1\7\2\uffff"
        )

            
    DFA125_transition = [
        DFA.unpack(u"\1\2\2\3\27\uffff\1\7\1\6\2\uffff\1\5\26\uffff\1\10"
        u"\1\4\53\uffff\1\1\3\3"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #125

    class DFA125(DFA):
        pass


        def specialStateTransition(self_, s, input):
            # convince pylint that my self_ magic is ok ;)
            # pylint: disable-msg=E0213

            # pretend we are a member of the recognizer
            # thus semantic predicates can be evaluated
            self = self_.recognizer

            _s = s

            if s == 0: 
                LA125_1 = input.LA(1)

                 
                index125_1 = input.index()
                input.rewind()
                s = -1
                if (self.synpred146_JavaScript()):
                    s = 9

                elif (True):
                    s = 10

                 
                input.seek(index125_1)
                if s >= 0:
                    return s
            elif s == 1: 
                LA125_2 = input.LA(1)

                 
                index125_2 = input.index()
                input.rewind()
                s = -1
                if (self.synpred146_JavaScript()):
                    s = 9

                elif (True):
                    s = 10

                 
                input.seek(index125_2)
                if s >= 0:
                    return s
            elif s == 2: 
                LA125_3 = input.LA(1)

                 
                index125_3 = input.index()
                input.rewind()
                s = -1
                if (self.synpred146_JavaScript()):
                    s = 9

                elif (True):
                    s = 10

                 
                input.seek(index125_3)
                if s >= 0:
                    return s
            elif s == 3: 
                LA125_4 = input.LA(1)

                 
                index125_4 = input.index()
                input.rewind()
                s = -1
                if (self.synpred146_JavaScript()):
                    s = 9

                elif (True):
                    s = 10

                 
                input.seek(index125_4)
                if s >= 0:
                    return s
            elif s == 4: 
                LA125_5 = input.LA(1)

                 
                index125_5 = input.index()
                input.rewind()
                s = -1
                if (self.synpred146_JavaScript()):
                    s = 9

                elif (True):
                    s = 10

                 
                input.seek(index125_5)
                if s >= 0:
                    return s
            elif s == 5: 
                LA125_6 = input.LA(1)

                 
                index125_6 = input.index()
                input.rewind()
                s = -1
                if (self.synpred146_JavaScript()):
                    s = 9

                elif (True):
                    s = 10

                 
                input.seek(index125_6)
                if s >= 0:
                    return s
            elif s == 6: 
                LA125_7 = input.LA(1)

                 
                index125_7 = input.index()
                input.rewind()
                s = -1
                if (self.synpred146_JavaScript()):
                    s = 9

                elif (True):
                    s = 10

                 
                input.seek(index125_7)
                if s >= 0:
                    return s
            elif s == 7: 
                LA125_8 = input.LA(1)

                 
                index125_8 = input.index()
                input.rewind()
                s = -1
                if (self.synpred146_JavaScript()):
                    s = 9

                elif (True):
                    s = 10

                 
                input.seek(index125_8)
                if s >= 0:
                    return s

            if self._state.backtracking >0:
                raise BacktrackingFailed
            nvae = NoViableAltException(self_.getDescription(), 125, _s, input)
            self_.error(nvae)
            raise nvae
    # lookup tables for DFA #127

    DFA127_eot = DFA.unpack(
        u"\12\uffff"
        )

    DFA127_eof = DFA.unpack(
        u"\12\uffff"
        )

    DFA127_min = DFA.unpack(
        u"\1\5\7\uffff\1\0\1\uffff"
        )

    DFA127_max = DFA.unpack(
        u"\1\152\7\uffff\1\0\1\uffff"
        )

    DFA127_accept = DFA.unpack(
        u"\1\uffff\1\1\7\uffff\1\2"
        )

    DFA127_special = DFA.unpack(
        u"\10\uffff\1\0\1\uffff"
        )

            
    DFA127_transition = [
        DFA.unpack(u"\3\1\27\uffff\2\1\2\uffff\1\1\26\uffff\1\10\1\1\53\uffff"
        u"\4\1"),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u"")
    ]

    # class definition for DFA #127

    class DFA127(DFA):
        pass


        def specialStateTransition(self_, s, input):
            # convince pylint that my self_ magic is ok ;)
            # pylint: disable-msg=E0213

            # pretend we are a member of the recognizer
            # thus semantic predicates can be evaluated
            self = self_.recognizer

            _s = s

            if s == 0: 
                LA127_8 = input.LA(1)

                 
                index127_8 = input.index()
                input.rewind()
                s = -1
                if (self.synpred147_JavaScript()):
                    s = 1

                elif (True):
                    s = 9

                 
                input.seek(index127_8)
                if s >= 0:
                    return s

            if self._state.backtracking >0:
                raise BacktrackingFailed
            nvae = NoViableAltException(self_.getDescription(), 127, _s, input)
            self_.error(nvae)
            raise nvae
    # lookup tables for DFA #132

    DFA132_eot = DFA.unpack(
        u"\32\uffff"
        )

    DFA132_eof = DFA.unpack(
        u"\1\2\31\uffff"
        )

    DFA132_min = DFA.unpack(
        u"\1\4\1\0\30\uffff"
        )

    DFA132_max = DFA.unpack(
        u"\1\144\1\0\30\uffff"
        )

    DFA132_accept = DFA.unpack(
        u"\2\uffff\1\2\25\uffff\1\1\1\uffff"
        )

    DFA132_special = DFA.unpack(
        u"\1\uffff\1\0\30\uffff"
        )

            
    DFA132_transition = [
        DFA.unpack(u"\1\1\33\uffff\3\2\1\uffff\1\2\1\uffff\2\2\5\uffff\1"
        u"\2\4\uffff\1\2\10\uffff\1\30\1\2\1\30\42\2\3\uffff\2\2"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #132

    class DFA132(DFA):
        pass


        def specialStateTransition(self_, s, input):
            # convince pylint that my self_ magic is ok ;)
            # pylint: disable-msg=E0213

            # pretend we are a member of the recognizer
            # thus semantic predicates can be evaluated
            self = self_.recognizer

            _s = s

            if s == 0: 
                LA132_1 = input.LA(1)

                 
                index132_1 = input.index()
                input.rewind()
                s = -1
                if (self.synpred154_JavaScript()):
                    s = 24

                elif (True):
                    s = 2

                 
                input.seek(index132_1)
                if s >= 0:
                    return s

            if self._state.backtracking >0:
                raise BacktrackingFailed
            nvae = NoViableAltException(self_.getDescription(), 132, _s, input)
            self_.error(nvae)
            raise nvae
    # lookup tables for DFA #136

    DFA136_eot = DFA.unpack(
        u"\32\uffff"
        )

    DFA136_eof = DFA.unpack(
        u"\1\2\31\uffff"
        )

    DFA136_min = DFA.unpack(
        u"\1\4\1\0\30\uffff"
        )

    DFA136_max = DFA.unpack(
        u"\1\144\1\0\30\uffff"
        )

    DFA136_accept = DFA.unpack(
        u"\2\uffff\1\2\24\uffff\1\1\2\uffff"
        )

    DFA136_special = DFA.unpack(
        u"\1\uffff\1\0\30\uffff"
        )

            
    DFA136_transition = [
        DFA.unpack(u"\1\1\33\uffff\1\27\2\2\1\uffff\1\2\1\uffff\2\2\5\uffff"
        u"\1\2\4\uffff\1\2\10\uffff\1\27\1\2\1\27\42\2\3\uffff\2\2"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #136

    class DFA136(DFA):
        pass


        def specialStateTransition(self_, s, input):
            # convince pylint that my self_ magic is ok ;)
            # pylint: disable-msg=E0213

            # pretend we are a member of the recognizer
            # thus semantic predicates can be evaluated
            self = self_.recognizer

            _s = s

            if s == 0: 
                LA136_1 = input.LA(1)

                 
                index136_1 = input.index()
                input.rewind()
                s = -1
                if (self.synpred158_JavaScript()):
                    s = 23

                elif (True):
                    s = 2

                 
                input.seek(index136_1)
                if s >= 0:
                    return s

            if self._state.backtracking >0:
                raise BacktrackingFailed
            nvae = NoViableAltException(self_.getDescription(), 136, _s, input)
            self_.error(nvae)
            raise nvae
    # lookup tables for DFA #142

    DFA142_eot = DFA.unpack(
        u"\4\uffff"
        )

    DFA142_eof = DFA.unpack(
        u"\4\uffff"
        )

    DFA142_min = DFA.unpack(
        u"\2\4\2\uffff"
        )

    DFA142_max = DFA.unpack(
        u"\2\152\2\uffff"
        )

    DFA142_accept = DFA.unpack(
        u"\2\uffff\1\1\1\2"
        )

    DFA142_special = DFA.unpack(
        u"\4\uffff"
        )

            
    DFA142_transition = [
        DFA.unpack(u"\1\1\3\2\27\uffff\2\2\1\uffff\1\3\1\2\26\uffff\2\2\37"
        u"\uffff\2\2\3\uffff\13\2"),
        DFA.unpack(u"\1\1\3\2\27\uffff\2\2\1\uffff\1\3\1\2\26\uffff\2\2"
        u"\37\uffff\2\2\3\uffff\13\2"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #142

    class DFA142(DFA):
        pass


    # lookup tables for DFA #141

    DFA141_eot = DFA.unpack(
        u"\4\uffff"
        )

    DFA141_eof = DFA.unpack(
        u"\4\uffff"
        )

    DFA141_min = DFA.unpack(
        u"\2\4\2\uffff"
        )

    DFA141_max = DFA.unpack(
        u"\2\42\2\uffff"
        )

    DFA141_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1"
        )

    DFA141_special = DFA.unpack(
        u"\4\uffff"
        )

            
    DFA141_transition = [
        DFA.unpack(u"\1\1\34\uffff\1\3\1\2"),
        DFA.unpack(u"\1\1\34\uffff\1\3\1\2"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #141

    class DFA141(DFA):
        pass


    # lookup tables for DFA #151

    DFA151_eot = DFA.unpack(
        u"\5\uffff"
        )

    DFA151_eof = DFA.unpack(
        u"\2\3\2\uffff\1\3"
        )

    DFA151_min = DFA.unpack(
        u"\2\4\2\uffff\1\4"
        )

    DFA151_max = DFA.unpack(
        u"\1\111\1\152\2\uffff\1\152"
        )

    DFA151_accept = DFA.unpack(
        u"\2\uffff\1\1\1\2\1\uffff"
        )

    DFA151_special = DFA.unpack(
        u"\5\uffff"
        )

            
    DFA151_transition = [
        DFA.unpack(u"\1\1\34\uffff\2\3\1\uffff\1\3\1\uffff\1\3\13\uffff\1"
        u"\3\11\uffff\1\3\14\uffff\1\2"),
        DFA.unpack(u"\1\4\3\3\27\uffff\10\3\1\uffff\5\3\1\uffff\12\3\2\uffff"
        u"\3\3\14\uffff\1\2\21\uffff\2\3\3\uffff\13\3"),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u"\1\4\3\3\27\uffff\10\3\1\uffff\5\3\1\uffff\12\3\2\uffff"
        u"\3\3\14\uffff\1\2\21\uffff\2\3\3\uffff\13\3")
    ]

    # class definition for DFA #151

    class DFA151(DFA):
        pass


    # lookup tables for DFA #156

    DFA156_eot = DFA.unpack(
        u"\4\uffff"
        )

    DFA156_eof = DFA.unpack(
        u"\1\3\3\uffff"
        )

    DFA156_min = DFA.unpack(
        u"\2\4\2\uffff"
        )

    DFA156_max = DFA.unpack(
        u"\2\111\2\uffff"
        )

    DFA156_accept = DFA.unpack(
        u"\2\uffff\1\1\1\2"
        )

    DFA156_special = DFA.unpack(
        u"\4\uffff"
        )

            
    DFA156_transition = [
        DFA.unpack(u"\1\1\34\uffff\1\3\4\uffff\1\3\6\uffff\1\3\4\uffff\1"
        u"\3\26\uffff\1\2"),
        DFA.unpack(u"\1\1\34\uffff\1\3\4\uffff\1\3\6\uffff\1\3\4\uffff\1"
        u"\3\26\uffff\1\2"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #156

    class DFA156(DFA):
        pass


    # lookup tables for DFA #159

    DFA159_eot = DFA.unpack(
        u"\5\uffff"
        )

    DFA159_eof = DFA.unpack(
        u"\2\2\2\uffff\1\2"
        )

    DFA159_min = DFA.unpack(
        u"\2\4\2\uffff\1\4"
        )

    DFA159_max = DFA.unpack(
        u"\1\112\1\152\2\uffff\1\152"
        )

    DFA159_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1\1\uffff"
        )

    DFA159_special = DFA.unpack(
        u"\5\uffff"
        )

            
    DFA159_transition = [
        DFA.unpack(u"\1\1\34\uffff\2\2\1\uffff\1\2\1\uffff\1\2\13\uffff\1"
        u"\2\11\uffff\1\2\14\uffff\1\2\1\3"),
        DFA.unpack(u"\1\4\3\2\27\uffff\10\2\1\uffff\5\2\1\uffff\12\2\2\uffff"
        u"\3\2\14\uffff\1\2\1\3\20\uffff\2\2\3\uffff\13\2"),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u"\1\4\3\2\27\uffff\10\2\1\uffff\5\2\1\uffff\12\2\2\uffff"
        u"\3\2\14\uffff\1\2\1\3\20\uffff\2\2\3\uffff\13\2")
    ]

    # class definition for DFA #159

    class DFA159(DFA):
        pass


    # lookup tables for DFA #162

    DFA162_eot = DFA.unpack(
        u"\4\uffff"
        )

    DFA162_eof = DFA.unpack(
        u"\1\2\3\uffff"
        )

    DFA162_min = DFA.unpack(
        u"\2\4\2\uffff"
        )

    DFA162_max = DFA.unpack(
        u"\2\112\2\uffff"
        )

    DFA162_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1"
        )

    DFA162_special = DFA.unpack(
        u"\4\uffff"
        )

            
    DFA162_transition = [
        DFA.unpack(u"\1\1\34\uffff\1\2\4\uffff\1\2\6\uffff\1\2\4\uffff\1"
        u"\2\26\uffff\1\2\1\3"),
        DFA.unpack(u"\1\1\34\uffff\1\2\4\uffff\1\2\6\uffff\1\2\4\uffff\1"
        u"\2\26\uffff\1\2\1\3"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #162

    class DFA162(DFA):
        pass


    # lookup tables for DFA #165

    DFA165_eot = DFA.unpack(
        u"\5\uffff"
        )

    DFA165_eof = DFA.unpack(
        u"\2\2\2\uffff\1\2"
        )

    DFA165_min = DFA.unpack(
        u"\2\4\2\uffff\1\4"
        )

    DFA165_max = DFA.unpack(
        u"\1\113\1\152\2\uffff\1\152"
        )

    DFA165_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1\1\uffff"
        )

    DFA165_special = DFA.unpack(
        u"\5\uffff"
        )

            
    DFA165_transition = [
        DFA.unpack(u"\1\1\34\uffff\2\2\1\uffff\1\2\1\uffff\1\2\13\uffff\1"
        u"\2\11\uffff\1\2\14\uffff\2\2\1\3"),
        DFA.unpack(u"\1\4\3\2\27\uffff\10\2\1\uffff\5\2\1\uffff\12\2\2\uffff"
        u"\3\2\14\uffff\2\2\1\3\17\uffff\2\2\3\uffff\13\2"),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u"\1\4\3\2\27\uffff\10\2\1\uffff\5\2\1\uffff\12\2\2\uffff"
        u"\3\2\14\uffff\2\2\1\3\17\uffff\2\2\3\uffff\13\2")
    ]

    # class definition for DFA #165

    class DFA165(DFA):
        pass


    # lookup tables for DFA #168

    DFA168_eot = DFA.unpack(
        u"\4\uffff"
        )

    DFA168_eof = DFA.unpack(
        u"\1\2\3\uffff"
        )

    DFA168_min = DFA.unpack(
        u"\2\4\2\uffff"
        )

    DFA168_max = DFA.unpack(
        u"\2\113\2\uffff"
        )

    DFA168_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1"
        )

    DFA168_special = DFA.unpack(
        u"\4\uffff"
        )

            
    DFA168_transition = [
        DFA.unpack(u"\1\1\34\uffff\1\2\4\uffff\1\2\6\uffff\1\2\4\uffff\1"
        u"\2\26\uffff\2\2\1\3"),
        DFA.unpack(u"\1\1\34\uffff\1\2\4\uffff\1\2\6\uffff\1\2\4\uffff\1"
        u"\2\26\uffff\2\2\1\3"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #168

    class DFA168(DFA):
        pass


    # lookup tables for DFA #171

    DFA171_eot = DFA.unpack(
        u"\5\uffff"
        )

    DFA171_eof = DFA.unpack(
        u"\2\2\2\uffff\1\2"
        )

    DFA171_min = DFA.unpack(
        u"\2\4\2\uffff\1\4"
        )

    DFA171_max = DFA.unpack(
        u"\1\114\1\152\2\uffff\1\152"
        )

    DFA171_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1\1\uffff"
        )

    DFA171_special = DFA.unpack(
        u"\5\uffff"
        )

            
    DFA171_transition = [
        DFA.unpack(u"\1\1\34\uffff\2\2\1\uffff\1\2\1\uffff\1\2\13\uffff\1"
        u"\2\11\uffff\1\2\14\uffff\3\2\1\3"),
        DFA.unpack(u"\1\4\3\2\27\uffff\10\2\1\uffff\5\2\1\uffff\12\2\2\uffff"
        u"\3\2\14\uffff\3\2\1\3\16\uffff\2\2\3\uffff\13\2"),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u"\1\4\3\2\27\uffff\10\2\1\uffff\5\2\1\uffff\12\2\2\uffff"
        u"\3\2\14\uffff\3\2\1\3\16\uffff\2\2\3\uffff\13\2")
    ]

    # class definition for DFA #171

    class DFA171(DFA):
        pass


    # lookup tables for DFA #174

    DFA174_eot = DFA.unpack(
        u"\4\uffff"
        )

    DFA174_eof = DFA.unpack(
        u"\1\2\3\uffff"
        )

    DFA174_min = DFA.unpack(
        u"\2\4\2\uffff"
        )

    DFA174_max = DFA.unpack(
        u"\2\114\2\uffff"
        )

    DFA174_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1"
        )

    DFA174_special = DFA.unpack(
        u"\4\uffff"
        )

            
    DFA174_transition = [
        DFA.unpack(u"\1\1\34\uffff\1\2\4\uffff\1\2\6\uffff\1\2\4\uffff\1"
        u"\2\26\uffff\3\2\1\3"),
        DFA.unpack(u"\1\1\34\uffff\1\2\4\uffff\1\2\6\uffff\1\2\4\uffff\1"
        u"\2\26\uffff\3\2\1\3"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #174

    class DFA174(DFA):
        pass


    # lookup tables for DFA #177

    DFA177_eot = DFA.unpack(
        u"\5\uffff"
        )

    DFA177_eof = DFA.unpack(
        u"\2\2\2\uffff\1\2"
        )

    DFA177_min = DFA.unpack(
        u"\2\4\2\uffff\1\4"
        )

    DFA177_max = DFA.unpack(
        u"\1\115\1\152\2\uffff\1\152"
        )

    DFA177_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1\1\uffff"
        )

    DFA177_special = DFA.unpack(
        u"\5\uffff"
        )

            
    DFA177_transition = [
        DFA.unpack(u"\1\1\34\uffff\2\2\1\uffff\1\2\1\uffff\1\2\13\uffff\1"
        u"\2\11\uffff\1\2\14\uffff\4\2\1\3"),
        DFA.unpack(u"\1\4\3\2\27\uffff\10\2\1\uffff\5\2\1\uffff\12\2\2\uffff"
        u"\3\2\14\uffff\4\2\1\3\15\uffff\2\2\3\uffff\13\2"),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u"\1\4\3\2\27\uffff\10\2\1\uffff\5\2\1\uffff\12\2\2\uffff"
        u"\3\2\14\uffff\4\2\1\3\15\uffff\2\2\3\uffff\13\2")
    ]

    # class definition for DFA #177

    class DFA177(DFA):
        pass


    # lookup tables for DFA #180

    DFA180_eot = DFA.unpack(
        u"\4\uffff"
        )

    DFA180_eof = DFA.unpack(
        u"\1\2\3\uffff"
        )

    DFA180_min = DFA.unpack(
        u"\2\4\2\uffff"
        )

    DFA180_max = DFA.unpack(
        u"\2\115\2\uffff"
        )

    DFA180_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1"
        )

    DFA180_special = DFA.unpack(
        u"\4\uffff"
        )

            
    DFA180_transition = [
        DFA.unpack(u"\1\1\34\uffff\1\2\4\uffff\1\2\6\uffff\1\2\4\uffff\1"
        u"\2\26\uffff\4\2\1\3"),
        DFA.unpack(u"\1\1\34\uffff\1\2\4\uffff\1\2\6\uffff\1\2\4\uffff\1"
        u"\2\26\uffff\4\2\1\3"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #180

    class DFA180(DFA):
        pass


    # lookup tables for DFA #183

    DFA183_eot = DFA.unpack(
        u"\5\uffff"
        )

    DFA183_eof = DFA.unpack(
        u"\2\2\2\uffff\1\2"
        )

    DFA183_min = DFA.unpack(
        u"\2\4\2\uffff\1\4"
        )

    DFA183_max = DFA.unpack(
        u"\1\116\1\152\2\uffff\1\152"
        )

    DFA183_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1\1\uffff"
        )

    DFA183_special = DFA.unpack(
        u"\5\uffff"
        )

            
    DFA183_transition = [
        DFA.unpack(u"\1\1\34\uffff\2\2\1\uffff\1\2\1\uffff\1\2\13\uffff\1"
        u"\2\11\uffff\1\2\14\uffff\5\2\1\3"),
        DFA.unpack(u"\1\4\3\2\27\uffff\10\2\1\uffff\5\2\1\uffff\12\2\2\uffff"
        u"\3\2\14\uffff\5\2\1\3\14\uffff\2\2\3\uffff\13\2"),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u"\1\4\3\2\27\uffff\10\2\1\uffff\5\2\1\uffff\12\2\2\uffff"
        u"\3\2\14\uffff\5\2\1\3\14\uffff\2\2\3\uffff\13\2")
    ]

    # class definition for DFA #183

    class DFA183(DFA):
        pass


    # lookup tables for DFA #186

    DFA186_eot = DFA.unpack(
        u"\4\uffff"
        )

    DFA186_eof = DFA.unpack(
        u"\1\2\3\uffff"
        )

    DFA186_min = DFA.unpack(
        u"\2\4\2\uffff"
        )

    DFA186_max = DFA.unpack(
        u"\2\116\2\uffff"
        )

    DFA186_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1"
        )

    DFA186_special = DFA.unpack(
        u"\4\uffff"
        )

            
    DFA186_transition = [
        DFA.unpack(u"\1\1\34\uffff\1\2\4\uffff\1\2\6\uffff\1\2\4\uffff\1"
        u"\2\26\uffff\5\2\1\3"),
        DFA.unpack(u"\1\1\34\uffff\1\2\4\uffff\1\2\6\uffff\1\2\4\uffff\1"
        u"\2\26\uffff\5\2\1\3"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #186

    class DFA186(DFA):
        pass


    # lookup tables for DFA #189

    DFA189_eot = DFA.unpack(
        u"\5\uffff"
        )

    DFA189_eof = DFA.unpack(
        u"\2\2\2\uffff\1\2"
        )

    DFA189_min = DFA.unpack(
        u"\2\4\2\uffff\1\4"
        )

    DFA189_max = DFA.unpack(
        u"\1\122\1\152\2\uffff\1\152"
        )

    DFA189_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1\1\uffff"
        )

    DFA189_special = DFA.unpack(
        u"\5\uffff"
        )

            
    DFA189_transition = [
        DFA.unpack(u"\1\1\34\uffff\2\2\1\uffff\1\2\1\uffff\1\2\13\uffff\1"
        u"\2\11\uffff\1\2\14\uffff\6\2\4\3"),
        DFA.unpack(u"\1\4\3\2\27\uffff\10\2\1\uffff\5\2\1\uffff\12\2\2\uffff"
        u"\3\2\14\uffff\6\2\4\3\10\uffff\2\2\3\uffff\13\2"),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u"\1\4\3\2\27\uffff\10\2\1\uffff\5\2\1\uffff\12\2\2\uffff"
        u"\3\2\14\uffff\6\2\4\3\10\uffff\2\2\3\uffff\13\2")
    ]

    # class definition for DFA #189

    class DFA189(DFA):
        pass


    # lookup tables for DFA #192

    DFA192_eot = DFA.unpack(
        u"\4\uffff"
        )

    DFA192_eof = DFA.unpack(
        u"\1\2\3\uffff"
        )

    DFA192_min = DFA.unpack(
        u"\2\4\2\uffff"
        )

    DFA192_max = DFA.unpack(
        u"\2\122\2\uffff"
        )

    DFA192_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1"
        )

    DFA192_special = DFA.unpack(
        u"\4\uffff"
        )

            
    DFA192_transition = [
        DFA.unpack(u"\1\1\34\uffff\1\2\4\uffff\1\2\6\uffff\1\2\4\uffff\1"
        u"\2\26\uffff\6\2\4\3"),
        DFA.unpack(u"\1\1\34\uffff\1\2\4\uffff\1\2\6\uffff\1\2\4\uffff\1"
        u"\2\26\uffff\6\2\4\3"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #192

    class DFA192(DFA):
        pass


    # lookup tables for DFA #195

    DFA195_eot = DFA.unpack(
        u"\5\uffff"
        )

    DFA195_eof = DFA.unpack(
        u"\2\2\2\uffff\1\2"
        )

    DFA195_min = DFA.unpack(
        u"\2\4\2\uffff\1\4"
        )

    DFA195_max = DFA.unpack(
        u"\1\127\1\152\2\uffff\1\152"
        )

    DFA195_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1\1\uffff"
        )

    DFA195_special = DFA.unpack(
        u"\5\uffff"
        )

            
    DFA195_transition = [
        DFA.unpack(u"\1\1\34\uffff\2\2\1\uffff\1\2\1\uffff\1\2\6\uffff\1"
        u"\3\4\uffff\1\2\11\uffff\1\2\14\uffff\12\2\5\3"),
        DFA.unpack(u"\1\4\3\2\27\uffff\10\2\1\uffff\5\2\1\3\12\2\2\uffff"
        u"\3\2\14\uffff\12\2\5\3\3\uffff\2\2\3\uffff\13\2"),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u"\1\4\3\2\27\uffff\10\2\1\uffff\5\2\1\3\12\2\2\uffff"
        u"\3\2\14\uffff\12\2\5\3\3\uffff\2\2\3\uffff\13\2")
    ]

    # class definition for DFA #195

    class DFA195(DFA):
        pass


    # lookup tables for DFA #198

    DFA198_eot = DFA.unpack(
        u"\4\uffff"
        )

    DFA198_eof = DFA.unpack(
        u"\1\2\3\uffff"
        )

    DFA198_min = DFA.unpack(
        u"\2\4\2\uffff"
        )

    DFA198_max = DFA.unpack(
        u"\2\127\2\uffff"
        )

    DFA198_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1"
        )

    DFA198_special = DFA.unpack(
        u"\4\uffff"
        )

            
    DFA198_transition = [
        DFA.unpack(u"\1\1\34\uffff\1\2\4\uffff\1\2\6\uffff\1\2\4\uffff\1"
        u"\2\26\uffff\12\2\5\3"),
        DFA.unpack(u"\1\1\34\uffff\1\2\4\uffff\1\2\6\uffff\1\2\4\uffff\1"
        u"\2\26\uffff\12\2\5\3"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #198

    class DFA198(DFA):
        pass


    # lookup tables for DFA #201

    DFA201_eot = DFA.unpack(
        u"\5\uffff"
        )

    DFA201_eof = DFA.unpack(
        u"\2\2\2\uffff\1\2"
        )

    DFA201_min = DFA.unpack(
        u"\2\4\2\uffff\1\4"
        )

    DFA201_max = DFA.unpack(
        u"\1\132\1\152\2\uffff\1\152"
        )

    DFA201_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1\1\uffff"
        )

    DFA201_special = DFA.unpack(
        u"\5\uffff"
        )

            
    DFA201_transition = [
        DFA.unpack(u"\1\1\34\uffff\2\2\1\uffff\1\2\1\uffff\1\2\6\uffff\1"
        u"\2\4\uffff\1\2\11\uffff\1\2\14\uffff\17\2\3\3"),
        DFA.unpack(u"\1\4\3\2\27\uffff\10\2\1\uffff\20\2\2\uffff\3\2\14"
        u"\uffff\17\2\3\3\2\2\3\uffff\13\2"),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u"\1\4\3\2\27\uffff\10\2\1\uffff\20\2\2\uffff\3\2\14"
        u"\uffff\17\2\3\3\2\2\3\uffff\13\2")
    ]

    # class definition for DFA #201

    class DFA201(DFA):
        pass


    # lookup tables for DFA #204

    DFA204_eot = DFA.unpack(
        u"\24\uffff"
        )

    DFA204_eof = DFA.unpack(
        u"\1\2\23\uffff"
        )

    DFA204_min = DFA.unpack(
        u"\1\4\1\0\22\uffff"
        )

    DFA204_max = DFA.unpack(
        u"\1\134\1\0\22\uffff"
        )

    DFA204_accept = DFA.unpack(
        u"\2\uffff\1\2\20\uffff\1\1"
        )

    DFA204_special = DFA.unpack(
        u"\1\uffff\1\0\22\uffff"
        )

            
    DFA204_transition = [
        DFA.unpack(u"\1\1\34\uffff\2\2\1\uffff\1\2\1\uffff\1\2\6\uffff\1"
        u"\2\4\uffff\1\2\11\uffff\1\2\14\uffff\22\2\2\23"),
        DFA.unpack(u"\1\uffff"),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #204

    class DFA204(DFA):
        pass


        def specialStateTransition(self_, s, input):
            # convince pylint that my self_ magic is ok ;)
            # pylint: disable-msg=E0213

            # pretend we are a member of the recognizer
            # thus semantic predicates can be evaluated
            self = self_.recognizer

            _s = s

            if s == 0: 
                LA204_1 = input.LA(1)

                 
                index204_1 = input.index()
                input.rewind()
                s = -1
                if (self.synpred256_JavaScript()):
                    s = 19

                elif (True):
                    s = 2

                 
                input.seek(index204_1)
                if s >= 0:
                    return s

            if self._state.backtracking >0:
                raise BacktrackingFailed
            nvae = NoViableAltException(self_.getDescription(), 204, _s, input)
            self_.error(nvae)
            raise nvae
    # lookup tables for DFA #207

    DFA207_eot = DFA.unpack(
        u"\5\uffff"
        )

    DFA207_eof = DFA.unpack(
        u"\2\2\2\uffff\1\2"
        )

    DFA207_min = DFA.unpack(
        u"\2\4\2\uffff\1\4"
        )

    DFA207_max = DFA.unpack(
        u"\1\137\1\152\2\uffff\1\152"
        )

    DFA207_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1\1\uffff"
        )

    DFA207_special = DFA.unpack(
        u"\5\uffff"
        )

            
    DFA207_transition = [
        DFA.unpack(u"\1\1\34\uffff\2\2\1\uffff\1\2\1\uffff\1\2\6\uffff\1"
        u"\2\4\uffff\1\2\11\uffff\1\2\14\uffff\24\2\3\3"),
        DFA.unpack(u"\1\4\3\2\27\uffff\10\2\1\uffff\20\2\2\uffff\3\2\14"
        u"\uffff\24\2\3\3\13\2"),
        DFA.unpack(u""),
        DFA.unpack(u""),
        DFA.unpack(u"\1\4\3\2\27\uffff\10\2\1\uffff\20\2\2\uffff\3\2\14"
        u"\uffff\24\2\3\3\13\2")
    ]

    # class definition for DFA #207

    class DFA207(DFA):
        pass


    # lookup tables for DFA #218

    DFA218_eot = DFA.unpack(
        u"\4\uffff"
        )

    DFA218_eof = DFA.unpack(
        u"\4\uffff"
        )

    DFA218_min = DFA.unpack(
        u"\2\4\2\uffff"
        )

    DFA218_max = DFA.unpack(
        u"\2\74\2\uffff"
        )

    DFA218_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1"
        )

    DFA218_special = DFA.unpack(
        u"\4\uffff"
        )

            
    DFA218_transition = [
        DFA.unpack(u"\1\1\34\uffff\1\3\32\uffff\1\2"),
        DFA.unpack(u"\1\1\34\uffff\1\3\32\uffff\1\2"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #218

    class DFA218(DFA):
        pass


    # lookup tables for DFA #217

    DFA217_eot = DFA.unpack(
        u"\4\uffff"
        )

    DFA217_eof = DFA.unpack(
        u"\4\uffff"
        )

    DFA217_min = DFA.unpack(
        u"\2\4\2\uffff"
        )

    DFA217_max = DFA.unpack(
        u"\2\152\2\uffff"
        )

    DFA217_accept = DFA.unpack(
        u"\2\uffff\1\1\1\2"
        )

    DFA217_special = DFA.unpack(
        u"\4\uffff"
        )

            
    DFA217_transition = [
        DFA.unpack(u"\1\1\3\2\27\uffff\2\2\1\3\1\uffff\1\2\26\uffff\2\2\1"
        u"\3\36\uffff\2\2\3\uffff\13\2"),
        DFA.unpack(u"\1\1\3\2\27\uffff\2\2\1\3\1\uffff\1\2\26\uffff\2\2"
        u"\1\3\36\uffff\2\2\3\uffff\13\2"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #217

    class DFA217(DFA):
        pass


    # lookup tables for DFA #223

    DFA223_eot = DFA.unpack(
        u"\4\uffff"
        )

    DFA223_eof = DFA.unpack(
        u"\4\uffff"
        )

    DFA223_min = DFA.unpack(
        u"\2\4\2\uffff"
        )

    DFA223_max = DFA.unpack(
        u"\2\44\2\uffff"
        )

    DFA223_accept = DFA.unpack(
        u"\2\uffff\1\2\1\1"
        )

    DFA223_special = DFA.unpack(
        u"\4\uffff"
        )

            
    DFA223_transition = [
        DFA.unpack(u"\1\1\34\uffff\1\3\2\uffff\1\2"),
        DFA.unpack(u"\1\1\34\uffff\1\3\2\uffff\1\2"),
        DFA.unpack(u""),
        DFA.unpack(u"")
    ]

    # class definition for DFA #223

    class DFA223(DFA):
        pass


 

    FOLLOW_LT_in_program43 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_sourceElements_in_program47 = frozenset([4])
    FOLLOW_LT_in_program49 = frozenset([4])
    FOLLOW_EOF_in_program53 = frozenset([1])
    FOLLOW_sourceElement_in_sourceElements66 = frozenset([1, 4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_sourceElements69 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_sourceElement_in_sourceElements73 = frozenset([1, 4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_functionDeclaration_in_sourceElement87 = frozenset([1])
    FOLLOW_statement_in_sourceElement92 = frozenset([1])
    FOLLOW_31_in_functionDeclaration105 = frozenset([4, 5])
    FOLLOW_LT_in_functionDeclaration107 = frozenset([4, 5])
    FOLLOW_Identifier_in_functionDeclaration111 = frozenset([4, 32])
    FOLLOW_LT_in_functionDeclaration113 = frozenset([4, 32])
    FOLLOW_formalParameterList_in_functionDeclaration117 = frozenset([4, 35])
    FOLLOW_LT_in_functionDeclaration119 = frozenset([4, 35])
    FOLLOW_functionBody_in_functionDeclaration123 = frozenset([1])
    FOLLOW_31_in_functionExpression135 = frozenset([4, 5, 32])
    FOLLOW_LT_in_functionExpression137 = frozenset([4, 5, 32])
    FOLLOW_Identifier_in_functionExpression141 = frozenset([4, 32])
    FOLLOW_LT_in_functionExpression144 = frozenset([4, 32])
    FOLLOW_formalParameterList_in_functionExpression148 = frozenset([4, 35])
    FOLLOW_LT_in_functionExpression150 = frozenset([4, 35])
    FOLLOW_functionBody_in_functionExpression154 = frozenset([1])
    FOLLOW_32_in_formalParameterList166 = frozenset([4, 5, 34])
    FOLLOW_LT_in_formalParameterList169 = frozenset([4, 5])
    FOLLOW_Identifier_in_formalParameterList173 = frozenset([4, 33, 34])
    FOLLOW_LT_in_formalParameterList176 = frozenset([4, 33])
    FOLLOW_33_in_formalParameterList180 = frozenset([4, 5])
    FOLLOW_LT_in_formalParameterList182 = frozenset([4, 5])
    FOLLOW_Identifier_in_formalParameterList186 = frozenset([4, 33, 34])
    FOLLOW_LT_in_formalParameterList192 = frozenset([4, 34])
    FOLLOW_34_in_formalParameterList196 = frozenset([1])
    FOLLOW_35_in_functionBody207 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_functionBody209 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_sourceElements_in_functionBody213 = frozenset([4, 36])
    FOLLOW_LT_in_functionBody215 = frozenset([4, 36])
    FOLLOW_36_in_functionBody219 = frozenset([1])
    FOLLOW_statementBlock_in_statement231 = frozenset([1])
    FOLLOW_variableStatement_in_statement236 = frozenset([1])
    FOLLOW_emptyStatement_in_statement241 = frozenset([1])
    FOLLOW_expressionStatement_in_statement246 = frozenset([1])
    FOLLOW_ifStatement_in_statement251 = frozenset([1])
    FOLLOW_iterationStatement_in_statement256 = frozenset([1])
    FOLLOW_continueStatement_in_statement261 = frozenset([1])
    FOLLOW_breakStatement_in_statement266 = frozenset([1])
    FOLLOW_returnStatement_in_statement271 = frozenset([1])
    FOLLOW_withStatement_in_statement276 = frozenset([1])
    FOLLOW_labelledStatement_in_statement281 = frozenset([1])
    FOLLOW_switchStatement_in_statement286 = frozenset([1])
    FOLLOW_throwStatement_in_statement291 = frozenset([1])
    FOLLOW_tryStatement_in_statement296 = frozenset([1])
    FOLLOW_35_in_statementBlock308 = frozenset([4, 5, 6, 7, 31, 32, 35, 36, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_statementBlock310 = frozenset([4, 5, 6, 7, 31, 32, 35, 36, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_statementList_in_statementBlock314 = frozenset([4, 36])
    FOLLOW_LT_in_statementBlock317 = frozenset([4, 36])
    FOLLOW_36_in_statementBlock321 = frozenset([1])
    FOLLOW_statement_in_statementList333 = frozenset([1, 4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_statementList336 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_statement_in_statementList340 = frozenset([1, 4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_37_in_variableStatement354 = frozenset([4, 5])
    FOLLOW_LT_in_variableStatement356 = frozenset([4, 5])
    FOLLOW_variableDeclarationList_in_variableStatement360 = frozenset([4, 38])
    FOLLOW_set_in_variableStatement362 = frozenset([1])
    FOLLOW_variableDeclaration_in_variableDeclarationList381 = frozenset([1, 4, 33])
    FOLLOW_LT_in_variableDeclarationList384 = frozenset([4, 33])
    FOLLOW_33_in_variableDeclarationList388 = frozenset([4, 5])
    FOLLOW_LT_in_variableDeclarationList390 = frozenset([4, 5])
    FOLLOW_variableDeclaration_in_variableDeclarationList394 = frozenset([1, 4, 33])
    FOLLOW_variableDeclarationNoIn_in_variableDeclarationListNoIn408 = frozenset([1, 4, 33])
    FOLLOW_LT_in_variableDeclarationListNoIn411 = frozenset([4, 33])
    FOLLOW_33_in_variableDeclarationListNoIn415 = frozenset([4, 5])
    FOLLOW_LT_in_variableDeclarationListNoIn417 = frozenset([4, 5])
    FOLLOW_variableDeclarationNoIn_in_variableDeclarationListNoIn421 = frozenset([1, 4, 33])
    FOLLOW_Identifier_in_variableDeclaration435 = frozenset([1, 4, 39])
    FOLLOW_LT_in_variableDeclaration437 = frozenset([1, 4, 39])
    FOLLOW_initialiser_in_variableDeclaration441 = frozenset([1])
    FOLLOW_Identifier_in_variableDeclarationNoIn454 = frozenset([1, 4, 39])
    FOLLOW_LT_in_variableDeclarationNoIn456 = frozenset([1, 4, 39])
    FOLLOW_initialiserNoIn_in_variableDeclarationNoIn460 = frozenset([1])
    FOLLOW_39_in_initialiser473 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_initialiser475 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_assignmentExpression_in_initialiser479 = frozenset([1])
    FOLLOW_39_in_initialiserNoIn491 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_initialiserNoIn493 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_assignmentExpressionNoIn_in_initialiserNoIn497 = frozenset([1])
    FOLLOW_38_in_emptyStatement509 = frozenset([1])
    FOLLOW_expression_in_expressionStatement521 = frozenset([4, 38])
    FOLLOW_set_in_expressionStatement523 = frozenset([1])
    FOLLOW_40_in_ifStatement542 = frozenset([4, 32])
    FOLLOW_LT_in_ifStatement544 = frozenset([4, 32])
    FOLLOW_32_in_ifStatement548 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_ifStatement550 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_expression_in_ifStatement554 = frozenset([4, 34])
    FOLLOW_LT_in_ifStatement556 = frozenset([4, 34])
    FOLLOW_34_in_ifStatement560 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_ifStatement562 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_statement_in_ifStatement566 = frozenset([1, 4, 41])
    FOLLOW_LT_in_ifStatement569 = frozenset([4, 41])
    FOLLOW_41_in_ifStatement573 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_ifStatement575 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_statement_in_ifStatement579 = frozenset([1])
    FOLLOW_doWhileStatement_in_iterationStatement593 = frozenset([1])
    FOLLOW_whileStatement_in_iterationStatement598 = frozenset([1])
    FOLLOW_forStatement_in_iterationStatement603 = frozenset([1])
    FOLLOW_forInStatement_in_iterationStatement608 = frozenset([1])
    FOLLOW_42_in_doWhileStatement620 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_doWhileStatement622 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_statement_in_doWhileStatement626 = frozenset([4, 43])
    FOLLOW_LT_in_doWhileStatement628 = frozenset([4, 43])
    FOLLOW_43_in_doWhileStatement632 = frozenset([4, 32])
    FOLLOW_LT_in_doWhileStatement634 = frozenset([4, 32])
    FOLLOW_32_in_doWhileStatement638 = frozenset([5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_expression_in_doWhileStatement640 = frozenset([34])
    FOLLOW_34_in_doWhileStatement642 = frozenset([4, 38])
    FOLLOW_set_in_doWhileStatement644 = frozenset([1])
    FOLLOW_43_in_whileStatement663 = frozenset([4, 32])
    FOLLOW_LT_in_whileStatement665 = frozenset([4, 32])
    FOLLOW_32_in_whileStatement669 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_whileStatement671 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_expression_in_whileStatement675 = frozenset([4, 34])
    FOLLOW_LT_in_whileStatement677 = frozenset([4, 34])
    FOLLOW_34_in_whileStatement681 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_whileStatement683 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_statement_in_whileStatement687 = frozenset([1])
    FOLLOW_44_in_forStatement699 = frozenset([4, 32])
    FOLLOW_LT_in_forStatement701 = frozenset([4, 32])
    FOLLOW_32_in_forStatement705 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 38, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_forStatement708 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_forStatementInitialiserPart_in_forStatement712 = frozenset([4, 38])
    FOLLOW_LT_in_forStatement716 = frozenset([4, 38])
    FOLLOW_38_in_forStatement720 = frozenset([4, 5, 6, 7, 31, 32, 35, 38, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_forStatement723 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_expression_in_forStatement727 = frozenset([4, 38])
    FOLLOW_LT_in_forStatement731 = frozenset([4, 38])
    FOLLOW_38_in_forStatement735 = frozenset([4, 5, 6, 7, 31, 32, 34, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_forStatement738 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_expression_in_forStatement742 = frozenset([4, 34])
    FOLLOW_LT_in_forStatement746 = frozenset([4, 34])
    FOLLOW_34_in_forStatement750 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_forStatement752 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_statement_in_forStatement756 = frozenset([1])
    FOLLOW_expressionNoIn_in_forStatementInitialiserPart768 = frozenset([1])
    FOLLOW_37_in_forStatementInitialiserPart773 = frozenset([4, 5])
    FOLLOW_LT_in_forStatementInitialiserPart775 = frozenset([4, 5])
    FOLLOW_variableDeclarationListNoIn_in_forStatementInitialiserPart779 = frozenset([1])
    FOLLOW_44_in_forInStatement791 = frozenset([4, 32])
    FOLLOW_LT_in_forInStatement793 = frozenset([4, 32])
    FOLLOW_32_in_forInStatement797 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 58, 59, 103, 104, 105, 106])
    FOLLOW_LT_in_forInStatement799 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 58, 59, 103, 104, 105, 106])
    FOLLOW_forInStatementInitialiserPart_in_forInStatement803 = frozenset([4, 45])
    FOLLOW_LT_in_forInStatement805 = frozenset([4, 45])
    FOLLOW_45_in_forInStatement809 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_forInStatement811 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_expression_in_forInStatement815 = frozenset([4, 34])
    FOLLOW_LT_in_forInStatement817 = frozenset([4, 34])
    FOLLOW_34_in_forInStatement821 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_forInStatement823 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_statement_in_forInStatement827 = frozenset([1])
    FOLLOW_leftHandSideExpression_in_forInStatementInitialiserPart839 = frozenset([1])
    FOLLOW_37_in_forInStatementInitialiserPart844 = frozenset([4, 5])
    FOLLOW_LT_in_forInStatementInitialiserPart846 = frozenset([4, 5])
    FOLLOW_variableDeclarationNoIn_in_forInStatementInitialiserPart850 = frozenset([1])
    FOLLOW_46_in_continueStatement861 = frozenset([4, 5, 38])
    FOLLOW_Identifier_in_continueStatement863 = frozenset([4, 38])
    FOLLOW_set_in_continueStatement866 = frozenset([1])
    FOLLOW_47_in_breakStatement884 = frozenset([4, 5, 38])
    FOLLOW_Identifier_in_breakStatement886 = frozenset([4, 38])
    FOLLOW_set_in_breakStatement889 = frozenset([1])
    FOLLOW_48_in_returnStatement907 = frozenset([4, 5, 6, 7, 31, 32, 35, 38, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_expression_in_returnStatement909 = frozenset([4, 38])
    FOLLOW_set_in_returnStatement912 = frozenset([1])
    FOLLOW_49_in_withStatement931 = frozenset([4, 32])
    FOLLOW_LT_in_withStatement933 = frozenset([4, 32])
    FOLLOW_32_in_withStatement937 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_withStatement939 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_expression_in_withStatement943 = frozenset([4, 34])
    FOLLOW_LT_in_withStatement945 = frozenset([4, 34])
    FOLLOW_34_in_withStatement949 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_withStatement951 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_statement_in_withStatement955 = frozenset([1])
    FOLLOW_Identifier_in_labelledStatement966 = frozenset([4, 50])
    FOLLOW_LT_in_labelledStatement968 = frozenset([4, 50])
    FOLLOW_50_in_labelledStatement972 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_labelledStatement974 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_statement_in_labelledStatement978 = frozenset([1])
    FOLLOW_51_in_switchStatement990 = frozenset([4, 32])
    FOLLOW_LT_in_switchStatement992 = frozenset([4, 32])
    FOLLOW_32_in_switchStatement996 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_switchStatement998 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_expression_in_switchStatement1002 = frozenset([4, 34])
    FOLLOW_LT_in_switchStatement1004 = frozenset([4, 34])
    FOLLOW_34_in_switchStatement1008 = frozenset([4, 35])
    FOLLOW_LT_in_switchStatement1010 = frozenset([4, 35])
    FOLLOW_caseBlock_in_switchStatement1014 = frozenset([1])
    FOLLOW_35_in_caseBlock1026 = frozenset([4, 36, 52, 53])
    FOLLOW_LT_in_caseBlock1029 = frozenset([4, 52])
    FOLLOW_caseClause_in_caseBlock1033 = frozenset([4, 36, 52, 53])
    FOLLOW_LT_in_caseBlock1038 = frozenset([4, 53])
    FOLLOW_defaultClause_in_caseBlock1042 = frozenset([4, 36, 52])
    FOLLOW_LT_in_caseBlock1045 = frozenset([4, 52])
    FOLLOW_caseClause_in_caseBlock1049 = frozenset([4, 36, 52])
    FOLLOW_LT_in_caseBlock1055 = frozenset([4, 36])
    FOLLOW_36_in_caseBlock1059 = frozenset([1])
    FOLLOW_52_in_caseClause1070 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_caseClause1072 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_expression_in_caseClause1076 = frozenset([4, 50])
    FOLLOW_LT_in_caseClause1078 = frozenset([4, 50])
    FOLLOW_50_in_caseClause1082 = frozenset([1, 4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_caseClause1084 = frozenset([1, 4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_statementList_in_caseClause1088 = frozenset([1])
    FOLLOW_53_in_defaultClause1101 = frozenset([4, 50])
    FOLLOW_LT_in_defaultClause1103 = frozenset([4, 50])
    FOLLOW_50_in_defaultClause1107 = frozenset([1, 4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_defaultClause1109 = frozenset([1, 4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_statementList_in_defaultClause1113 = frozenset([1])
    FOLLOW_54_in_throwStatement1126 = frozenset([5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_expression_in_throwStatement1128 = frozenset([4, 38])
    FOLLOW_set_in_throwStatement1130 = frozenset([1])
    FOLLOW_55_in_tryStatement1148 = frozenset([4, 35])
    FOLLOW_LT_in_tryStatement1150 = frozenset([4, 35])
    FOLLOW_statementBlock_in_tryStatement1154 = frozenset([4, 56, 57])
    FOLLOW_LT_in_tryStatement1156 = frozenset([4, 56, 57])
    FOLLOW_finallyClause_in_tryStatement1161 = frozenset([1])
    FOLLOW_catchClause_in_tryStatement1165 = frozenset([1, 4, 57])
    FOLLOW_LT_in_tryStatement1168 = frozenset([4, 57])
    FOLLOW_finallyClause_in_tryStatement1172 = frozenset([1])
    FOLLOW_56_in_catchClause1193 = frozenset([4, 32])
    FOLLOW_LT_in_catchClause1195 = frozenset([4, 32])
    FOLLOW_32_in_catchClause1199 = frozenset([4, 5])
    FOLLOW_LT_in_catchClause1201 = frozenset([4, 5])
    FOLLOW_Identifier_in_catchClause1205 = frozenset([4, 34])
    FOLLOW_LT_in_catchClause1207 = frozenset([4, 34])
    FOLLOW_34_in_catchClause1211 = frozenset([4, 35])
    FOLLOW_LT_in_catchClause1213 = frozenset([4, 35])
    FOLLOW_statementBlock_in_catchClause1217 = frozenset([1])
    FOLLOW_57_in_finallyClause1229 = frozenset([4, 35])
    FOLLOW_LT_in_finallyClause1231 = frozenset([4, 35])
    FOLLOW_statementBlock_in_finallyClause1235 = frozenset([1])
    FOLLOW_assignmentExpression_in_expression1247 = frozenset([1, 4, 33])
    FOLLOW_LT_in_expression1250 = frozenset([4, 33])
    FOLLOW_33_in_expression1254 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_expression1256 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_assignmentExpression_in_expression1260 = frozenset([1, 4, 33])
    FOLLOW_assignmentExpressionNoIn_in_expressionNoIn1274 = frozenset([1, 4, 33])
    FOLLOW_LT_in_expressionNoIn1277 = frozenset([4, 33])
    FOLLOW_33_in_expressionNoIn1281 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_expressionNoIn1283 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_assignmentExpressionNoIn_in_expressionNoIn1287 = frozenset([1, 4, 33])
    FOLLOW_conditionalExpression_in_assignmentExpression1301 = frozenset([1])
    FOLLOW_leftHandSideExpression_in_assignmentExpression1306 = frozenset([4, 39, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72])
    FOLLOW_LT_in_assignmentExpression1308 = frozenset([4, 39, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72])
    FOLLOW_assignmentOperator_in_assignmentExpression1312 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_assignmentExpression1314 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_assignmentExpression_in_assignmentExpression1318 = frozenset([1])
    FOLLOW_conditionalExpressionNoIn_in_assignmentExpressionNoIn1330 = frozenset([1])
    FOLLOW_leftHandSideExpression_in_assignmentExpressionNoIn1335 = frozenset([4, 39, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72])
    FOLLOW_LT_in_assignmentExpressionNoIn1337 = frozenset([4, 39, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72])
    FOLLOW_assignmentOperator_in_assignmentExpressionNoIn1341 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_assignmentExpressionNoIn1343 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_assignmentExpressionNoIn_in_assignmentExpressionNoIn1347 = frozenset([1])
    FOLLOW_callExpression_in_leftHandSideExpression1359 = frozenset([1])
    FOLLOW_newExpression_in_leftHandSideExpression1364 = frozenset([1])
    FOLLOW_memberExpression_in_newExpression1376 = frozenset([1])
    FOLLOW_58_in_newExpression1381 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 103, 104, 105, 106])
    FOLLOW_LT_in_newExpression1383 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 103, 104, 105, 106])
    FOLLOW_newExpression_in_newExpression1387 = frozenset([1])
    FOLLOW_primaryExpression_in_memberExpression1400 = frozenset([1, 4, 59, 61])
    FOLLOW_functionExpression_in_memberExpression1404 = frozenset([1, 4, 59, 61])
    FOLLOW_58_in_memberExpression1408 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 103, 104, 105, 106])
    FOLLOW_LT_in_memberExpression1410 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 103, 104, 105, 106])
    FOLLOW_memberExpression_in_memberExpression1414 = frozenset([4, 32])
    FOLLOW_LT_in_memberExpression1416 = frozenset([4, 32])
    FOLLOW_arguments_in_memberExpression1420 = frozenset([1, 4, 59, 61])
    FOLLOW_LT_in_memberExpression1424 = frozenset([4, 59, 61])
    FOLLOW_memberExpressionSuffix_in_memberExpression1428 = frozenset([1, 4, 59, 61])
    FOLLOW_indexSuffix_in_memberExpressionSuffix1442 = frozenset([1])
    FOLLOW_propertyReferenceSuffix_in_memberExpressionSuffix1447 = frozenset([1])
    FOLLOW_memberExpression_in_callExpression1458 = frozenset([4, 32])
    FOLLOW_LT_in_callExpression1460 = frozenset([4, 32])
    FOLLOW_arguments_in_callExpression1464 = frozenset([1, 4, 32, 59, 61])
    FOLLOW_LT_in_callExpression1467 = frozenset([4, 32, 59, 61])
    FOLLOW_callExpressionSuffix_in_callExpression1471 = frozenset([1, 4, 32, 59, 61])
    FOLLOW_arguments_in_callExpressionSuffix1485 = frozenset([1])
    FOLLOW_indexSuffix_in_callExpressionSuffix1490 = frozenset([1])
    FOLLOW_propertyReferenceSuffix_in_callExpressionSuffix1495 = frozenset([1])
    FOLLOW_32_in_arguments1506 = frozenset([4, 5, 6, 7, 31, 32, 34, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_arguments1509 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_assignmentExpression_in_arguments1513 = frozenset([4, 33, 34])
    FOLLOW_LT_in_arguments1516 = frozenset([4, 33])
    FOLLOW_33_in_arguments1520 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_arguments1522 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_assignmentExpression_in_arguments1526 = frozenset([4, 33, 34])
    FOLLOW_LT_in_arguments1532 = frozenset([4, 34])
    FOLLOW_34_in_arguments1536 = frozenset([1])
    FOLLOW_59_in_indexSuffix1548 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_indexSuffix1550 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_expression_in_indexSuffix1554 = frozenset([4, 60])
    FOLLOW_LT_in_indexSuffix1556 = frozenset([4, 60])
    FOLLOW_60_in_indexSuffix1560 = frozenset([1])
    FOLLOW_61_in_propertyReferenceSuffix1573 = frozenset([4, 5])
    FOLLOW_LT_in_propertyReferenceSuffix1575 = frozenset([4, 5])
    FOLLOW_Identifier_in_propertyReferenceSuffix1579 = frozenset([1])
    FOLLOW_set_in_assignmentOperator0 = frozenset([1])
    FOLLOW_logicalORExpression_in_conditionalExpression1646 = frozenset([1, 4, 73])
    FOLLOW_LT_in_conditionalExpression1649 = frozenset([4, 73])
    FOLLOW_73_in_conditionalExpression1653 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_conditionalExpression1655 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_assignmentExpression_in_conditionalExpression1659 = frozenset([4, 50])
    FOLLOW_LT_in_conditionalExpression1661 = frozenset([4, 50])
    FOLLOW_50_in_conditionalExpression1665 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_conditionalExpression1667 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_assignmentExpression_in_conditionalExpression1671 = frozenset([1])
    FOLLOW_logicalORExpressionNoIn_in_conditionalExpressionNoIn1684 = frozenset([1, 4, 73])
    FOLLOW_LT_in_conditionalExpressionNoIn1687 = frozenset([4, 73])
    FOLLOW_73_in_conditionalExpressionNoIn1691 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_conditionalExpressionNoIn1693 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_assignmentExpressionNoIn_in_conditionalExpressionNoIn1697 = frozenset([4, 50])
    FOLLOW_LT_in_conditionalExpressionNoIn1699 = frozenset([4, 50])
    FOLLOW_50_in_conditionalExpressionNoIn1703 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_conditionalExpressionNoIn1705 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_assignmentExpressionNoIn_in_conditionalExpressionNoIn1709 = frozenset([1])
    FOLLOW_logicalANDExpression_in_logicalORExpression1722 = frozenset([1, 4, 74])
    FOLLOW_LT_in_logicalORExpression1725 = frozenset([4, 74])
    FOLLOW_74_in_logicalORExpression1729 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_logicalORExpression1731 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_logicalANDExpression_in_logicalORExpression1735 = frozenset([1, 4, 74])
    FOLLOW_logicalANDExpressionNoIn_in_logicalORExpressionNoIn1749 = frozenset([1, 4, 74])
    FOLLOW_LT_in_logicalORExpressionNoIn1752 = frozenset([4, 74])
    FOLLOW_74_in_logicalORExpressionNoIn1756 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_logicalORExpressionNoIn1758 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_logicalANDExpressionNoIn_in_logicalORExpressionNoIn1762 = frozenset([1, 4, 74])
    FOLLOW_bitwiseORExpression_in_logicalANDExpression1776 = frozenset([1, 4, 75])
    FOLLOW_LT_in_logicalANDExpression1779 = frozenset([4, 75])
    FOLLOW_75_in_logicalANDExpression1783 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_logicalANDExpression1785 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_bitwiseORExpression_in_logicalANDExpression1789 = frozenset([1, 4, 75])
    FOLLOW_bitwiseORExpressionNoIn_in_logicalANDExpressionNoIn1803 = frozenset([1, 4, 75])
    FOLLOW_LT_in_logicalANDExpressionNoIn1806 = frozenset([4, 75])
    FOLLOW_75_in_logicalANDExpressionNoIn1810 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_logicalANDExpressionNoIn1812 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_bitwiseORExpressionNoIn_in_logicalANDExpressionNoIn1816 = frozenset([1, 4, 75])
    FOLLOW_bitwiseXORExpression_in_bitwiseORExpression1830 = frozenset([1, 4, 76])
    FOLLOW_LT_in_bitwiseORExpression1833 = frozenset([4, 76])
    FOLLOW_76_in_bitwiseORExpression1837 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_bitwiseORExpression1839 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_bitwiseXORExpression_in_bitwiseORExpression1843 = frozenset([1, 4, 76])
    FOLLOW_bitwiseXORExpressionNoIn_in_bitwiseORExpressionNoIn1857 = frozenset([1, 4, 76])
    FOLLOW_LT_in_bitwiseORExpressionNoIn1860 = frozenset([4, 76])
    FOLLOW_76_in_bitwiseORExpressionNoIn1864 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_bitwiseORExpressionNoIn1866 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_bitwiseXORExpressionNoIn_in_bitwiseORExpressionNoIn1870 = frozenset([1, 4, 76])
    FOLLOW_bitwiseANDExpression_in_bitwiseXORExpression1884 = frozenset([1, 4, 77])
    FOLLOW_LT_in_bitwiseXORExpression1887 = frozenset([4, 77])
    FOLLOW_77_in_bitwiseXORExpression1891 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_bitwiseXORExpression1893 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_bitwiseANDExpression_in_bitwiseXORExpression1897 = frozenset([1, 4, 77])
    FOLLOW_bitwiseANDExpressionNoIn_in_bitwiseXORExpressionNoIn1911 = frozenset([1, 4, 77])
    FOLLOW_LT_in_bitwiseXORExpressionNoIn1914 = frozenset([4, 77])
    FOLLOW_77_in_bitwiseXORExpressionNoIn1918 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_bitwiseXORExpressionNoIn1920 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_bitwiseANDExpressionNoIn_in_bitwiseXORExpressionNoIn1924 = frozenset([1, 4, 77])
    FOLLOW_equalityExpression_in_bitwiseANDExpression1938 = frozenset([1, 4, 78])
    FOLLOW_LT_in_bitwiseANDExpression1941 = frozenset([4, 78])
    FOLLOW_78_in_bitwiseANDExpression1945 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_bitwiseANDExpression1947 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_equalityExpression_in_bitwiseANDExpression1951 = frozenset([1, 4, 78])
    FOLLOW_equalityExpressionNoIn_in_bitwiseANDExpressionNoIn1965 = frozenset([1, 4, 78])
    FOLLOW_LT_in_bitwiseANDExpressionNoIn1968 = frozenset([4, 78])
    FOLLOW_78_in_bitwiseANDExpressionNoIn1972 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_bitwiseANDExpressionNoIn1974 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_equalityExpressionNoIn_in_bitwiseANDExpressionNoIn1978 = frozenset([1, 4, 78])
    FOLLOW_relationalExpression_in_equalityExpression1992 = frozenset([1, 4, 79, 80, 81, 82])
    FOLLOW_LT_in_equalityExpression1995 = frozenset([4, 79, 80, 81, 82])
    FOLLOW_set_in_equalityExpression1999 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_equalityExpression2015 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_relationalExpression_in_equalityExpression2019 = frozenset([1, 4, 79, 80, 81, 82])
    FOLLOW_relationalExpressionNoIn_in_equalityExpressionNoIn2032 = frozenset([1, 4, 79, 80, 81, 82])
    FOLLOW_LT_in_equalityExpressionNoIn2035 = frozenset([4, 79, 80, 81, 82])
    FOLLOW_set_in_equalityExpressionNoIn2039 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_equalityExpressionNoIn2055 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_relationalExpressionNoIn_in_equalityExpressionNoIn2059 = frozenset([1, 4, 79, 80, 81, 82])
    FOLLOW_shiftExpression_in_relationalExpression2073 = frozenset([1, 4, 45, 83, 84, 85, 86, 87])
    FOLLOW_LT_in_relationalExpression2076 = frozenset([4, 45, 83, 84, 85, 86, 87])
    FOLLOW_set_in_relationalExpression2080 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_relationalExpression2104 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_shiftExpression_in_relationalExpression2108 = frozenset([1, 4, 45, 83, 84, 85, 86, 87])
    FOLLOW_shiftExpression_in_relationalExpressionNoIn2121 = frozenset([1, 4, 83, 84, 85, 86, 87])
    FOLLOW_LT_in_relationalExpressionNoIn2124 = frozenset([4, 83, 84, 85, 86, 87])
    FOLLOW_set_in_relationalExpressionNoIn2128 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_relationalExpressionNoIn2148 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_shiftExpression_in_relationalExpressionNoIn2152 = frozenset([1, 4, 83, 84, 85, 86, 87])
    FOLLOW_additiveExpression_in_shiftExpression2165 = frozenset([1, 4, 88, 89, 90])
    FOLLOW_LT_in_shiftExpression2168 = frozenset([4, 88, 89, 90])
    FOLLOW_set_in_shiftExpression2172 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_shiftExpression2184 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_additiveExpression_in_shiftExpression2188 = frozenset([1, 4, 88, 89, 90])
    FOLLOW_multiplicativeExpression_in_additiveExpression2201 = frozenset([1, 4, 91, 92])
    FOLLOW_LT_in_additiveExpression2204 = frozenset([4, 91, 92])
    FOLLOW_set_in_additiveExpression2208 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_additiveExpression2216 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_multiplicativeExpression_in_additiveExpression2220 = frozenset([1, 4, 91, 92])
    FOLLOW_unaryExpression_in_multiplicativeExpression2233 = frozenset([1, 4, 93, 94, 95])
    FOLLOW_LT_in_multiplicativeExpression2236 = frozenset([4, 93, 94, 95])
    FOLLOW_set_in_multiplicativeExpression2240 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_multiplicativeExpression2252 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_unaryExpression_in_multiplicativeExpression2256 = frozenset([1, 4, 93, 94, 95])
    FOLLOW_postfixExpression_in_unaryExpression2269 = frozenset([1])
    FOLLOW_set_in_unaryExpression2274 = frozenset([5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_unaryExpression_in_unaryExpression2310 = frozenset([1])
    FOLLOW_leftHandSideExpression_in_postfixExpression2322 = frozenset([1, 99, 100])
    FOLLOW_set_in_postfixExpression2324 = frozenset([1])
    FOLLOW_103_in_primaryExpression2342 = frozenset([1])
    FOLLOW_Identifier_in_primaryExpression2347 = frozenset([1])
    FOLLOW_literal_in_primaryExpression2352 = frozenset([1])
    FOLLOW_arrayLiteral_in_primaryExpression2357 = frozenset([1])
    FOLLOW_objectLiteral_in_primaryExpression2362 = frozenset([1])
    FOLLOW_32_in_primaryExpression2367 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_primaryExpression2369 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_expression_in_primaryExpression2373 = frozenset([4, 34])
    FOLLOW_LT_in_primaryExpression2375 = frozenset([4, 34])
    FOLLOW_34_in_primaryExpression2379 = frozenset([1])
    FOLLOW_59_in_arrayLiteral2392 = frozenset([4, 5, 6, 7, 31, 32, 33, 35, 58, 59, 60, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_arrayLiteral2394 = frozenset([4, 5, 6, 7, 31, 32, 33, 35, 58, 59, 60, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_assignmentExpression_in_arrayLiteral2398 = frozenset([4, 33, 60])
    FOLLOW_LT_in_arrayLiteral2402 = frozenset([4, 33])
    FOLLOW_33_in_arrayLiteral2406 = frozenset([4, 5, 6, 7, 31, 32, 33, 35, 58, 59, 60, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_arrayLiteral2409 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_assignmentExpression_in_arrayLiteral2413 = frozenset([4, 33, 60])
    FOLLOW_LT_in_arrayLiteral2419 = frozenset([4, 60])
    FOLLOW_60_in_arrayLiteral2423 = frozenset([1])
    FOLLOW_35_in_objectLiteral2442 = frozenset([4, 5, 6, 7])
    FOLLOW_LT_in_objectLiteral2444 = frozenset([4, 5, 6, 7])
    FOLLOW_propertyNameAndValue_in_objectLiteral2448 = frozenset([4, 33, 36])
    FOLLOW_LT_in_objectLiteral2451 = frozenset([4, 33])
    FOLLOW_33_in_objectLiteral2455 = frozenset([4, 5, 6, 7])
    FOLLOW_LT_in_objectLiteral2457 = frozenset([4, 5, 6, 7])
    FOLLOW_propertyNameAndValue_in_objectLiteral2461 = frozenset([4, 33, 36])
    FOLLOW_LT_in_objectLiteral2465 = frozenset([4, 36])
    FOLLOW_36_in_objectLiteral2469 = frozenset([1])
    FOLLOW_propertyName_in_propertyNameAndValue2481 = frozenset([4, 50])
    FOLLOW_LT_in_propertyNameAndValue2483 = frozenset([4, 50])
    FOLLOW_50_in_propertyNameAndValue2487 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_propertyNameAndValue2489 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_assignmentExpression_in_propertyNameAndValue2493 = frozenset([1])
    FOLLOW_set_in_propertyName0 = frozenset([1])
    FOLLOW_set_in_literal0 = frozenset([1])
    FOLLOW_functionDeclaration_in_synpred5_JavaScript87 = frozenset([1])
    FOLLOW_LT_in_synpred9_JavaScript137 = frozenset([1])
    FOLLOW_statementBlock_in_synpred21_JavaScript231 = frozenset([1])
    FOLLOW_expressionStatement_in_synpred24_JavaScript246 = frozenset([1])
    FOLLOW_labelledStatement_in_synpred31_JavaScript281 = frozenset([1])
    FOLLOW_LT_in_synpred34_JavaScript310 = frozenset([1])
    FOLLOW_LT_in_synpred47_JavaScript437 = frozenset([1])
    FOLLOW_LT_in_synpred49_JavaScript456 = frozenset([1])
    FOLLOW_LT_in_synpred60_JavaScript569 = frozenset([4, 41])
    FOLLOW_41_in_synpred60_JavaScript573 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_synpred60_JavaScript575 = frozenset([4, 5, 6, 7, 31, 32, 35, 37, 38, 40, 42, 43, 44, 46, 47, 48, 49, 51, 54, 55, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_statement_in_synpred60_JavaScript579 = frozenset([1])
    FOLLOW_forStatement_in_synpred63_JavaScript603 = frozenset([1])
    FOLLOW_LT_in_synpred118_JavaScript1084 = frozenset([1])
    FOLLOW_LT_in_synpred121_JavaScript1109 = frozenset([1])
    FOLLOW_conditionalExpression_in_synpred140_JavaScript1301 = frozenset([1])
    FOLLOW_conditionalExpressionNoIn_in_synpred143_JavaScript1330 = frozenset([1])
    FOLLOW_callExpression_in_synpred146_JavaScript1359 = frozenset([1])
    FOLLOW_memberExpression_in_synpred147_JavaScript1376 = frozenset([1])
    FOLLOW_LT_in_synpred154_JavaScript1424 = frozenset([4, 59, 61])
    FOLLOW_memberExpressionSuffix_in_synpred154_JavaScript1428 = frozenset([1])
    FOLLOW_LT_in_synpred158_JavaScript1467 = frozenset([4, 32, 59, 61])
    FOLLOW_callExpressionSuffix_in_synpred158_JavaScript1471 = frozenset([1])
    FOLLOW_LT_in_synpred256_JavaScript2204 = frozenset([4, 91, 92])
    FOLLOW_set_in_synpred256_JavaScript2208 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_LT_in_synpred256_JavaScript2216 = frozenset([4, 5, 6, 7, 31, 32, 35, 58, 59, 91, 92, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106])
    FOLLOW_multiplicativeExpression_in_synpred256_JavaScript2220 = frozenset([1])
    FOLLOW_LT_in_synpred280_JavaScript2394 = frozenset([1])



def main(argv, stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr):
    from antlr3.main import ParserMain
    main = ParserMain("JavaScriptLexer", JavaScriptParser)
    main.stdin = stdin
    main.stdout = stdout
    main.stderr = stderr
    main.execute(argv)


if __name__ == '__main__':
    main(sys.argv)
