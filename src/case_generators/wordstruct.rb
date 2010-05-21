require 'binstruct'

# A few structure definitions for messing with .doc files. Probably the most
# important is the WordFIB, as it's the map to all the other structures in
# the Table stream.
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt

module WordStructures

    class WordSPRM < Binstruct
        attr_reader :length_check
        parse {|buf|
            spra_table={0=>1,1=>1,2=>2,3=>4,4=>2,5=>2,6=>:variable,7=>3}
            endian :little
            bitfield(buf,16){|buf|
                unsigned buf, :spra, 3, "Size of SPRM argument"
                unsigned buf, :sgc, 3, "SPRM group - type of SPRM"
                unsigned buf, :fSpec, 1, "SPRM requires special handling"
                unsigned buf, :ismpd, 9, "Unique ID within sgc group"
            }
            if spra_table[self.spra]==:variable
                unsigned buf, :opLen, 8, "Operand length"
                @length_check=self.opLen
                string buf, :operand, self.opLen*8, "Parameter"
                group :sprastuff, :sgc, :opLen, :fSpec, :ispmd, :operand
            else
                @length_check=spra_table[self.spra]
                unsigned buf, :operand, spra_table[self.spra]*8, "Parameter"
                group :sprastuff, :spra, :sgc, :ispmd, :operand
            end
        }
    end

    class WordDgg < Binstruct
        parse{ |bitbuf|
            endian :little
            bitfield(bitbuf, 16) do |buf|
                unsigned buf, :recInstance, 12, "Object Identifier"
                unsigned buf, :recVer, 4, "Object version, 0xF for container"
            end
            unsigned bitbuf, :recType, 16, "RecType"
            unsigned bitbuf, :recLen, 32, "Content length"
            if self.recVer==0xF
                substruct_name=:substruct0
                mychunk=[bitbuf.slice!(0,self.recLen*8)].pack('B*')
                while mychunk.length > 0
                    substruct(mychunk, substruct_name, mychunk.length, WordStructures::WordDgg)
                    substruct_name=substruct_name.succ
                end
            else
                string bitbuf, :contents, self.recLen*8, "Contents"
            end
            if self[:contents]
                group :tv, :recInstance, :recVer, :recType, :contents
            else
                group :tl, :recInstance, :recVer, :recType, :recLen
            end
        }
    end

    class StructuredStorageHeader < Binstruct
        parse{|buf|
            endian :little
            hexstring buf, :sig, 8*8,	"Signature"
            hexstring buf, :classid, 16*8, "CLSID"
            unsigned buf, :minorver, 2*8, "Minor Version"
            unsigned buf, :majorver, 2*8, "Major Version"
            hexstring buf, :byteorder, 2*8, "Byte Order"
            unsigned buf, :sectorshift, 2*8, "Sector Shift (size)"
            unsigned buf, :minisectorshift, 2*8, "Mini Sector Shift (size)"
            unsigned buf, :res, 2*8, "Reserved"
            unsigned buf, :res1, 4*8, "Reserved1"
            unsigned buf, :res2, 4*8, "Reserved2"
            unsigned buf, :sectcount, 4*8, "Number of Sects"
            unsigned buf, :firstsect, 4*8, "First Sect Offset"
            unsigned buf, :transactionsig, 4*8, "Transaction Signature"
            unsigned buf, :minisectcutoff, 4*8, "Mini Stream Max Size"
            unsigned buf, :minifatstart, 4*8, "First Sect in Mini FAT chain"
            unsigned buf, :minifatcount, 4*8, "Number of Mini FAT Sects"
            unsigned buf, :difstart, 4*8, "First Sect in DIF chain"
            unsigned buf, :difcount, 4*8, "Number of DIF Sects"
            hexstring buf, :fat109, 436*8, "First 109 Sects"
        }
    end

    class WordFIB < Binstruct
        parse {|buf|

            endian :little
            unsigned buf, :wIdent, 16, "0 Magic number"
            unsigned buf, :nFib, 16, "2 FIB version written. This will be >= 101 for all Word 6.0 for[...]"
            unsigned buf, :nProduct, 16, "4 Product version written by"
            unsigned buf, :Lid, 16, "6 Language stamp --localized version In pre-WinWord 2.0 files t[...]"
            unsigned buf, :pnNext, 16, ""
            bitfield(buf,16) do |buf|
                unsigned buf, :fCrypto, 1, "REVIEW"
                unsigned buf, :fFarEast, 1, "REVIEW"
                unsigned buf, :fLoadOverride, 1, "REVIEW"
                unsigned buf, :fExtChar, 1, "Set when using extended character set in file"
                unsigned buf, :fWriteReservation, 1, "Set when file owner has made the file write reserved"
                unsigned buf, :fReadOnlyRecommended, 1, "Set when user has recommended that file be read read-only"
                unsigned buf, :fWhichTblStm, 1, "When 0, this fib refers to the table stream named ?0Table?, whe[...]"
                unsigned buf, :fEncrypted, 1, "Set if file is encrypted"
                unsigned buf, :cQuickSaves, 4, "Count of times file was quick saved"
                unsigned buf, :fHasPic, 1, "Set if file contains 1 or more pictures"
                unsigned buf, :fComplex, 1, "When 1, file is in complex, fast-saved format."
                unsigned buf, :fGlsy, 1, "Set if this document is a glossary"
                unsigned buf, :fDot, 1, "10 Set if this document is a template"
            end
            unsigned buf, :nFibBack, 16, "12 This file format is compatible with readers that understand [...]"
            unsigned buf, :lKey, 32, ""
            unsigned buf, :Envr, 8, "18 Environment in which file was created 0 created by Word for [...]"
            unsigned buf, :fMac, 1, "19 When 1, this file was last saved in the Macintosh environment"
            unsigned buf, :fEmptySpecial, 1, ""
            unsigned buf, :fLoadOverridePage, 1, ""
            unsigned buf, :fFutureSavedUndo, 1, ""
            unsigned buf, :fWord97Saved, 1, ""
            unsigned buf, :fSpare0, 3, ""
            unsigned buf, :Chs, 16, "20 Default extended character set id for text in document strea[...]"
            hexstring buf, :chsTables, 16, "22 Default extended character set id for text in internal data [...]"
            unsigned buf, :fcMin, 32, "24 File offset of first character of text. In non-complex files[...]"
            unsigned buf, :fcMac, 32, "28 File offset of last character of text in document text strea[...]"
            unsigned buf, :Csw, 16, "32 Count of fields in the array of ?shorts?"
            unsigned buf, :wMagicCreated, 16, ""
            unsigned buf, :wMagicRevised, 16, ""
            unsigned buf, :wMagicCreatedPrivate, 16, ""
            unsigned buf, :wMagicRevisedPrivate, 16, ""
            unsigned buf, :pnFbpChpFirst_W6, 16, "42 Not used"
            unsigned buf, :pnChpFirst_W6, 16, "44 Not used"
            unsigned buf, :cpnBteChp_W6, 16, "46 Not used"
            unsigned buf, :pnFbpPapFirst_W6, 16, "48 Not used"
            unsigned buf, :pnPapFirst_W6, 16, "50 Not used"
            unsigned buf, :cpnBtePap_W6, 16, "52 Not used"
            unsigned buf, :pnFbpLvcFirst_W6, 16, "54 Not used"
            unsigned buf, :pnLvcFirst_W6, 16, "56 Not used"
            unsigned buf, :cpnBteLvc_W6, 16, "58 Not used"
            unsigned buf, :lidFE, 16, "60 Language id if document was written by East Asian version of[...]"
            unsigned buf, :Clw, 16, "62 Number of fields in the array of longs"
            unsigned buf, :cbMac, 32, "64 File offset of last byte written to file + 1"
            unsigned buf, :lProductCreated, 32, ""
            unsigned buf, :lProductRevised, 32, "72 Decimal"
            unsigned buf, :ccpText, 32, "76 Length of main document text stream 1"
            unsigned buf, :ccpFtn, 32, "80 Length of footnote subdocument text stream"
            unsigned buf, :ccpHdd, 32, "84 Length of header subdocument text stream"
            unsigned buf, :ccpMcr, 32, "88 Length of macro subdocument text stream, which should now al[...]"
            unsigned buf, :ccpAtn, 32, "92 Length of annotation subdocument text stream"
            unsigned buf, :ccpEdn, 32, "96 Length of endnote subdocument text stream"
            unsigned buf, :ccpTxbx, 32, "100 Length of textbox subdocument text stream"
            unsigned buf, :ccpHdrTxbx, 32, "104 Length of header textbox subdocument text stream"
            unsigned buf, :pnFbpChpFirst, 32, "108 When there was insufficient memory for Word to expand the p[...]"
            unsigned buf, :pnChpFirst, 32, "112 The page number of the lowest numbered page in the document[...]"
            unsigned buf, :cpnBteChp, 32, "116 Count of CHPX FKPs recorded in file. In non-complex files i[...]"
            unsigned buf, :pnFbpPapFirst, 32, "120 When there was insufficient memory for Word to expand the p[...]"
            unsigned buf, :pnPapFirst, 32, "124 The page number of the lowest numbered page in the document[...]"
            unsigned buf, :cpnBtePap, 32, "128 Count of PAPX FKPs recorded in file. In non-complex files i[...]"
            unsigned buf, :pnFbpLvcFirst, 32, "132 When there was insufficient memory for Word to expand the p[...]"
            unsigned buf, :pnLvcFirst, 32, "136 The page number of the lowest numbered page in the document[...]"
            unsigned buf, :cpnBteLvc, 32, "140 Count of LVC FKPs recorded in file. In non-complex files if[...]"
            unsigned buf, :fcIslandFirst, 32, ""
            unsigned buf, :fcIslandLim, 32, ""
            unsigned buf, :Cfclcb, 16, "152 Number of fields in the array of FC/LCB pairs"
            unsigned buf, :fcStshfOrig, 32, "154 File offset of original allocation for STSH in table stream[...]"
            unsigned buf, :lcbStshfOrig, 32, "158 Count of bytes of original STSH allocation"
            unsigned buf, :fcStshf, 32, "162 Offset of STSH in table stream"
            unsigned buf, :lcbStshf, 32, "166 Count of bytes of current STSH allocation"
            unsigned buf, :fcPlcffndRef, 32, "170 Offset in table stream of footnote reference PLCF of FRD st[...]"
            unsigned buf, :lcbPlcffndRef, 32, "174 Count of bytes of footnote reference PLC== 0 if no footnote[...]"
            unsigned buf, :fcPlcffndTxt, 32, "178 Offset in table stream of footnote text PLC. CPs in PLC are[...]"
            unsigned buf, :lcbPlcffndTxt, 32, "182 Count of bytes of footnote text PLC. == 0 if no footnotes d[...]"
            unsigned buf, :fcPlcfandRef, 32, "186 Offset in table stream of annotation reference ATRDPre10 PL[...]"
            unsigned buf, :lcbPlcfandRef, 32, "190 Count of bytes of annotation reference PLC"
            unsigned buf, :fcPlcfandTxt, 32, "194 Offset in table stream of annotation text PLC. The CPs reco[...]"
            unsigned buf, :lcbPlcfandTxt, 32, "198 Count of bytes of the annotation text PLC"
            unsigned buf, :fcPlcfsed, 32, "202 Offset in table stream of section descriptor SED PLC. CPs i[...]"
            unsigned buf, :lcbPlcfsed, 32, "206 Count of bytes of section descriptor PLC"
            unsigned buf, :fcPlcpad, 32, "210 No longer used"
            unsigned buf, :lcbPlcpad, 32, "214 No longer used"
            unsigned buf, :fcPlcfphe, 32, "218 Offset in table stream of PHE PLC of paragraph heights. CPs[...]"
            unsigned buf, :lcbPlcfphe, 32, "222 Count of bytes of paragraph height PLC. ==0 when file is no[...]"
            unsigned buf, :fcSttbfglsy, 32, "226 Offset in table stream of glossary string table. This table[...]"
            unsigned buf, :lcbSttbfglsy, 32, "230 Count of bytes of glossary string table. == 0 for non-gloss[...]"
            unsigned buf, :fcPlcfglsy, 32, "234 Offset in table stream of glossary PLC. CPs in PLC are rela[...]"
            unsigned buf, :lcbPlcfglsy, 32, "238 Count of bytes of glossary PLC. == 0 for non-glossary docum[...]"
            unsigned buf, :fcPlcfhdd, 32, "242 Byte offset in table stream of header HDD PLC. CPs are rela[...]"
            unsigned buf, :lcbPlcfhdd, 32, "246 Count of bytes of header PLC. == 0 if document contains no [...]"
            unsigned buf, :fcPlcfbteChpx, 32, "250 Offset in table stream of character property bin table.PLC.[...]"
            unsigned buf, :lcbPlcfbteChpx, 32, "254 Count of bytes of character property bin table PLC"
            unsigned buf, :fcPlcfbtePapx, 32, "258 Offset in table stream of paragraph property bin table.PLC.[...]"
            unsigned buf, :lcbPlcfbtePapx, 32, "262 Count of bytes of paragraph property bin table PLC"
            unsigned buf, :fcPlcfsea, 32, "266 Offset in table stream of PLC reserved for private use. The[...]"
            unsigned buf, :lcbPlcfsea, 32, "270 Count of bytes of private use PLC"
            unsigned buf, :fcSttbfffn, 32, "274 Offset in table stream of font information STTBF. The sttbf[...]"
            unsigned buf, :lcbSttbfffn, 32, "278 Count of bytes in sttbfffn"
            unsigned buf, :fcPlcffldMom, 32, "282 Offset in table stream to the FLD PLC of field positions in[...]"
            unsigned buf, :lcbPlcffldMom, 32, "286 Count of bytes in plcffldMom"
            unsigned buf, :fcPlcffldHdr, 32, "290 Offset in table stream to the FLD PLC of field positions in[...]"
            unsigned buf, :lcbPlcffldHdr, 32, "294 Count of bytes in plcffldHdr"
            unsigned buf, :fcPlcffldFtn, 32, "298 Offset in table stream to the FLD PLC of field positions in[...]"
            unsigned buf, :lcbPlcffldFtn, 32, "302 Count of bytes in plcffldFtn"
            unsigned buf, :fcPlcffldAtn, 32, "306 Offset in table stream to the FLD PLC of field positions in[...]"
            unsigned buf, :lcbPlcffldAtn, 32, "310 Count of bytes in plcffldAtn"
            unsigned buf, :fcPlcffldMcr, 32, "314 No longer used"
            unsigned buf, :lcbPlcffldMcr, 32, "318 No longer used"
            unsigned buf, :fcSttbfbkmk, 32, "322 Offset in table stream of the STTBF that records bookmark n[...]"
            unsigned buf, :lcbSttbfbkmk, 32, "326 Count of bytes in Sttbfbkmk"
            unsigned buf, :fcPlcfbkf, 32, "330 Offset in table stream of the PLCF that records the beginni[...]"
            unsigned buf, :lcbPlcfbkf, 32, "334 Count of bytes in Plcfbkf"
            unsigned buf, :fcPlcfbkl, 32, "338 Offset in table stream of the PLCF that records the ending [...]"
            unsigned buf, :lcbPlcfbkl, 32, "342 Count of bytes in Plcfbkl"
            unsigned buf, :fcCmds, 32, "346 Offset in table stream of the macro commands. These command[...]"
            unsigned buf, :lcbCmds, 32, "350 Count of bytes of the data above."
            unsigned buf, :fcPlcmcr, 32, "354 No longer used"
            unsigned buf, :lcbPlcmcr, 32, "358 No longer used"
            unsigned buf, :fcSttbfmcr, 32, "362 No longer used"
            unsigned buf, :lcbSttbfmcr, 32, "366 No longer used"
            unsigned buf, :fcPrDrvr, 32, "370 Offset in table stream of the printer driver information (n[...]"
            unsigned buf, :lcbPrDrvr, 32, "374 Count of bytes of the printer driver information (names of [...]"
            unsigned buf, :fcPrEnvPort, 32, "378 Offset in table stream of the print environment in portrait[...]"
            unsigned buf, :lcbPrEnvPort, 32, "382 Count of bytes of the print environment in portrait mode"
            unsigned buf, :fcPrEnvLand, 32, "386 Offset in table stream of the print environment in landscap[...]"
            unsigned buf, :lcbPrEnvLand, 32, "390 Count of bytes of the print environment in landscape mode"
            unsigned buf, :fcWss, 32, "394 Offset in table stream of Window Save State data structure.[...]"
            unsigned buf, :lcbWss, 32, "398 Count of bytes of WSS. ==0 if unable to store the window st[...]"
            unsigned buf, :fcDop, 32, "402 Offset in table stream of document property data structure"
            unsigned buf, :lcbDop, 32, "406 Count of bytes of document properties"
            unsigned buf, :fcSttbfAssoc, 32, "410 Offset in table stream of STTBF of associated strings. The [...]"
            unsigned buf, :lcbSttbfAssoc, 32, "414 Count of bytes in SttbfAssoc"
            unsigned buf, :fcClx, 32, "418 Offset in table stream of beginning of information for comp[...]"
            unsigned buf, :lcbClx, 32, "422 Count of bytes of complex file information == 0 if file is [...]"
            unsigned buf, :fcPlcfpgdFtn, 32, "426 Not used"
            unsigned buf, :lcbPlcfpgdFtn, 32, "430 Not used"
            unsigned buf, :fcAutosaveSource, 32, "434 Offset in table stream of the name of the original file. fc[...]"
            unsigned buf, :lcbAutosaveSource, 32, "438 Count of bytes of the name of the original file."
            unsigned buf, :fcGrpXstAtnOwners, 32, "442 Offset in table stream of group of strings recording the na[...]"
            unsigned buf, :lcbGrpXstAtnOwners, 32, "446 Count of bytes of the group of strings"
            unsigned buf, :fcSttbfAtnbkmk, 32, "450 Offset in table stream of the sttbf that records names of b[...]"
            unsigned buf, :lcbSttbfAtnbkmk, 32, "454 Length in bytes of the sttbf that records names of bookmark[...]"
            unsigned buf, :fcPlcdoaMom, 32, "458 No longer used"
            unsigned buf, :lcbPlcdoaMom, 32, "462 No longer used"
            unsigned buf, :fcPlcdoaHdr, 32, "466 No longer used"
            unsigned buf, :lcbPlcdoaHdr, 32, "470 No longer used"
            unsigned buf, :fcPlcspaMom, 32, "474 Offset in table stream of the FSPA PLC for main document. =[...]"
            unsigned buf, :lcbPlcspaMom, 32, "478 Length in bytes of the FSPA PLC of the main document"
            unsigned buf, :fcPlcspaHdr, 32, "482 Offset in table stream of the FSPA PLC for header document.[...]"
            unsigned buf, :lcbPlcspaHdr, 32, "486 Length in bytes of the FSPA PLC of the header document."
            unsigned buf, :fcPlcfAtnbkf, 32, "490 Offset in table stream of BKF (bookmark first) PLC of the a[...]"
            unsigned buf, :lcbPlcfAtnbkf, 32, "494 Length in bytes of BKF (bookmark first) PLC of the annotati[...]"
            unsigned buf, :fcPlcfAtnbkl, 32, "498 Offset in table stream of BKL (bookmark last) PLC of the an[...]"
            unsigned buf, :lcbPlcfAtnbkl, 32, "502 Length in bytes of PLC marking the CP limits of the annotat[...]"
            unsigned buf, :fcPms, 32, "506 Offset in table stream of PMS (Print Merge State) informati[...]"
            unsigned buf, :lcbPms, 32, "510 Length in bytes of PMS. ==0 if no current print merge state[...]"
            unsigned buf, :fcFormFldSttbs, 32, "514 Offset in table stream of form field sttbf which contains s[...]"
            unsigned buf, :lcbFormFldSttbs, 32, "518 Length in bytes of form field sttbf"
            unsigned buf, :fcPlcfendRef, 32, "522 Offset in table stream of endnote reference PLCF of FRD str[...]"
            unsigned buf, :lcbPlcfendRef, 32, "526 Count of bytes of the plcfendRef"
            unsigned buf, :fcPlcfendTxt, 32, "530 Offset in table stream of plcfendRef which points to endnot[...]"
            unsigned buf, :lcbPlcfendTxt, 32, "534 Count of bytes for the above data"
            unsigned buf, :fcPlcffldEdn, 32, "538 Offset in table stream to FLD PLCF of field positions in th[...]"
            unsigned buf, :lcbPlcffldEdn, 32, "542 Count of bytes for the above data"
            unsigned buf, :fcPlcfpgdEdn, 32, "546 Not used"
            unsigned buf, :lcbPlcfpgdEdn, 32, "550 Not used"
            unsigned buf, :fcDggInfo, 32, "554 Offset in table stream of the Office Drawing object table d[...]"
            unsigned buf, :lcbDggInfo, 32, "558 Length in bytes of the Office Drawing object table data"
            unsigned buf, :fcSttbfRMark, 32, "562 Offset in table stream to STTBF that records the author abb[...]"
            unsigned buf, :lcbSttbfRMark, 32, "566 Count of bytes for the above data"
            unsigned buf, :fcSttbCaption, 32, "570 Offset in table stream to STTBF that records caption titles[...]"
            unsigned buf, :lcbSttbCaption, 32, "574 Count of bytes for the above data"
            unsigned buf, :fcSttbAutoCaption, 32, "578 Offset in table stream to the STTBF that records the object[...]"
            unsigned buf, :lcbSttbAutoCaption, 32, "582 Count of bytes for the above data"
            unsigned buf, :fcPlcfwkb, 32, "586 Offset in table stream to WKB PLCF that describes the bound[...]"
            unsigned buf, :lcbPlcfwkb, 32, "590 Count of bytes for the above data"
            unsigned buf, :fcPlcfspl, 32, "594 Offset in table stream of PLCF (of SPLS structures) that re[...]"
            unsigned buf, :lcbPlcfspl, 32, "598 Count of bytes for the above data"
            unsigned buf, :fcPlcftxbxTxt, 32, "602 Offset in table stream of PLCF that records the beginning C[...]"
            unsigned buf, :lcbPlcftxbxTxt, 32, "606 Count of bytes for the above data"
            unsigned buf, :fcPlcffldTxbx, 32, "610 Offset in table stream of the FLD PLCF that records field b[...]"
            unsigned buf, :lcbPlcffldTxbx, 32, "614 Count of bytes for the above data"
            unsigned buf, :fcPlcfhdrtxbxTxt, 32, "618 Offset in table stream of PLCF that records the beginning C[...]"
            unsigned buf, :lcbPlcfhdrtxbxTxt, 32, "622 Count of bytes for the above data"
            unsigned buf, :fcPlcffldHdrTxbx, 32, "626 Offset in table stream of the FLD PLCF that records field b[...]"
            unsigned buf, :lcbPlcffldHdrTxbx, 32, "630 Count of bytes for the above data"
            unsigned buf, :fcStwUser, 32, "634 Macro user storage"
            unsigned buf, :lcbStwUser, 32, "638 Count of bytes for the above data"
            unsigned buf, :fcSttbttmbd, 32, "642 Offset in table stream of embedded true type font data"
            unsigned buf, :cbSttbttmbd, 32, "646 Count of bytes for the above data"
            unsigned buf, :fcCookieData, 32, "650 NLCheck error handle will persist in file"
            unsigned buf, :lcbCookieData, 32, "654 Count of bytes for the above data"
            unsigned buf, :fcpgdMotherOldOld, 128, "658 Offsets in table stream of the PLF that records the page an[...]"
            unsigned buf, :fcpgdFtnOldOld, 128, "674 Offsets in table stream of the PLF that records the page an[...]"
            unsigned buf, :fcpgdEdnOldOld, 128, "690 Offsets in table stream of the PLF that records the page an[...]"
            unsigned buf, :fcSttbfIntlFld, 32, "706 Offset in table stream of the STTBF containing field keywor[...]"
            unsigned buf, :lcbSttbfIntlFld, 32, "710 Always 0 for nFib>=167"
            unsigned buf, :fcRouteSlip, 32, "714 Offset in table stream of a mailer routing slip"
            unsigned buf, :lcbRouteSlip, 32, "718 Count of bytes for the above data"
            unsigned buf, :fcSttbSavedBy, 32, "722 Offset in table stream of STTBF recording the names of the [...]"
            unsigned buf, :lcbSttbSavedBy, 32, "726 Count of bytes for the above data"
            unsigned buf, :fcSttbFnm, 32, "730 Offset in table stream of STTBF recording filenames of docu[...]"
            unsigned buf, :lcbSttbFnm, 32, "734 Count of bytes for the above data"
            unsigned buf, :fcPlcfLst, 32, "738 Offset in the table stream of list format information"
            unsigned buf, :lcbPlcfLst, 32, "742 Count of bytes for the above data"
            unsigned buf, :fcPlfLfo, 32, "746 Offset in the table stream of list format override informat[...]"
            unsigned buf, :lcbPlfLfo, 32, "750 Count of bytes for the above data"
            unsigned buf, :fcPlcftxbxBkd, 32, "754 Offset in the table stream of the textbox break table (a PL[...]"
            unsigned buf, :lcbPlcftxbxBkd, 32, "758 Count of bytes for the above data"
            unsigned buf, :fcPlcftxbxHdrBkd, 32, "762 Offset in the table stream of the textbox break table (a PL[...]"
            unsigned buf, :lcbPlcftxbxHdrBkd, 32, "766 Count of bytes for the above data"
            unsigned buf, :fcDocUndoWord9, 32, "770 Offset in main stream of undocumented undo / versioning dat[...]"
            unsigned buf, :lcbDocUndoWord9, 32, "774 Count of bytes for the above data"
            unsigned buf, :fcRgbuse, 32, "778 Offset in main stream of undocumented undo / versioning data"
            unsigned buf, :lcbRgbuse, 32, "782 Count of bytes for the above data"
            unsigned buf, :fcUsp, 32, "786 Offset in main stream of undocumented undo / versioning data"
            unsigned buf, :lcbUsp, 32, "790 Count of bytes for the above data"
            unsigned buf, :fcUskf, 32, "794 Offset in table stream of undocumented undo / versioning da[...]"
            unsigned buf, :lcbUskf, 32, "798 Count of bytes for the above data"
            unsigned buf, :fcPlcupcRgbuse, 32, "802 Offset in table stream of undocumented undo / versioning da[...]"
            unsigned buf, :lcbPlcupcRgbuse, 32, "806 Count of bytes for the above data"
            unsigned buf, :fcPlcupcUsp, 32, "810 Offset in table stream of undocumented undo / versioning da[...]"
            unsigned buf, :lcbPlcupcUsp, 32, "814 Count of bytes for the above data"
            unsigned buf, :fcSttbGlsyStyle, 32, "818 Offset in table stream of string table of style names for g[...]"
            unsigned buf, :lcbSttbGlsyStyle, 32, "822 Count of bytes for the above data"
            unsigned buf, :fcPlgosl, 32, "826 Offset in table stream of undocumented grammar options PL"
            unsigned buf, :lcbPlgosl, 32, "830 Count of bytes for the above data"
            unsigned buf, :fcPlcocx, 32, "834 Offset in table stream of undocumented ocx data"
            unsigned buf, :lcbPlcocx, 32, "838 Count of bytes for the above data"
            unsigned buf, :fcPlcfbteLvc, 32, "842 Offset in table stream of character property bin table.PLC.[...]"
            unsigned buf, :lcbPlcfbteLvc, 32, "846 Count of bytes for the above data"
            unsigned buf, :dwLowDateTime, 32, ""
            unsigned buf, :dwHighDateTime, 32, ""
            unsigned buf, :fcPlcflvcPre10, 32, "858 Offset in table stream of LVC PLCF used pre Word10"
            unsigned buf, :lcbPlcflvcPre10, 32, "862 Size of LVC PLCF, ==0 for non-complex files"
            unsigned buf, :fcPlcasumy, 32, "866 Offset in table stream of autosummary ASUMY PLCF."
            unsigned buf, :lcbPlcasumy, 32, "870 Count of bytes for the above data"
            unsigned buf, :fcPlcfgram, 32, "874 Offset in table stream of PLCF (of SPLS structures) which r[...]"
            unsigned buf, :lcbPlcfgram, 32, "878 Count of bytes for the above data"
            unsigned buf, :fcSttbListNames, 32, "882 Offset in table stream of list names string table"
            unsigned buf, :lcbSttbListNames, 32, "886 Count of bytes for the above data"
            unsigned buf, :fcSttbfUssr, 32, "890 Offset in table stream of undocumented undo / versioning da[...]"
            unsigned buf, :lcbSttbfUssr, 32, "894 Count of bytes for the above data"
            unsigned buf, :fcPlcfTch, 32, "898 Offset in table stream of table chars This is an internal c[...]"
            unsigned buf, :lcbPlcfTch, 32, "902 Count of bytes of the above data"
            unsigned buf, :fcRmdfThreading, 32, "906 Offset in table stream of revision mark data This informati[...]"
            unsigned buf, :lcbRmdfThreading, 32, "910 Count of bytes for the above data"
            unsigned buf, :fcMid, 32, "914 Offset in table stream of Message ID (if any) This informat[...]"
            unsigned buf, :lcbMid, 32, "918 Count of bytes for the above data"
            unsigned buf, :fcSttbRgtplc, 32, "922 Offset in table stream of list gallery data (tplcs) This is[...]"
            unsigned buf, :lcbSttbRgtplc, 32, "926 Count of bytes for the above data"
            unsigned buf, :fcMsoEnvelope, 32, "930 Offset in table stream of persist the mail envelope This is[...]"
            unsigned buf, :lcbMsoEnvelope, 32, "934 Count of bytes for the above data"
            unsigned buf, :fcPlcflad, 32, "938 Offset in table stream of Language Auto Detect results This[...]"
            unsigned buf, :lcbPlcflad, 32, "942 Count of bytes for the above data"
            unsigned buf, :fcRgdofr, 32, "946 Document File Records (miscellaneous document data) This is[...]"
            unsigned buf, :lcbRgdofr, 32, "950 Count of bytes for the above data"
            unsigned buf, :fcPlcosl, 32, "954 Offset in table stream of NLCheck grammar option state per [...]"
            unsigned buf, :lcbPlcosl, 32, "958 Count of bytes for the above data"
            unsigned buf, :fcPlcfcookieOld, 32, "962 Offset in table stream of NLCheck error handle pre Word10 T[...]"
            unsigned buf, :lcbPlcfcookieOld, 32, "966 Count of bytes for the above data"
            unsigned buf, :fcpgdMotherOld, 128, "970 Main document repagination cache: used internally by Word T[...]"
            unsigned buf, :fcpgdFtnOld, 128, "986 Footnotes repagination cache: used internally by Word This [...]"
            unsigned buf, :fcpgdEdnOld, 128, "1002 Endnotes repagination cache: used internally by Word This [...]"
            unsigned buf, :fcUnused, 32, "1018 Not used"
            unsigned buf, :lcbUnused, 32, "1022 Not used"
            unsigned buf, :fcPlcfpgp, 32, "1026 Offset in table stream of Paragraph Group Properties This [...]"
            unsigned buf, :lcbPlcfpgp, 32, "1030 Count of bytes for the above data"
            unsigned buf, :fcPlcfuim, 32, "1034 Offset in table stream of UIM property data This is intern[...]"
            unsigned buf, :lcbPlcfium, 32, "1038 Count of bytes for the above data"
            unsigned buf, :fcPlfguidUim, 32, "1042 Offset in table stream of UIM table of GUIDs This is inter[...]"
            unsigned buf, :lcbPlfguidUim, 32, "1046 Count of bytes for the above data"
            unsigned buf, :fcAtrdExtra, 32, "1050 Offset in table stream of plex of ATRDPost10 structures"
            unsigned buf, :lcbAtrdExtra, 32, "1054 Count of bytes for the above data"
            unsigned buf, :fcPlrsid, 32, "1058 Offset in table stream of RSID plex. This is undocumented [...]"
            unsigned buf, :lcbPlrsid, 32, "1062 Count of bytes for the above data"
            unsigned buf, :fcSttbfBkmkFactoid, 32, "1066 Offset in table stream of smart tag bookmark STTB This is [...]"
            unsigned buf, :lcbSttbfBkmkFactoid, 32, "1070 Count of bytes for the above data"
            unsigned buf, :fcPlcfBkfFactoid, 32, "1074 Offset in table stream of smart tag bookmark plc of cpFirs[...]"
            unsigned buf, :lcbPlcfBkfFactoid, 32, "1078 Count of bytes for the above data"
            unsigned buf, :fcPlcfcookie, 32, "1082 Offset in table stream of whether the NLCheck error handle[...]"
            unsigned buf, :lcbPlcfcookie, 32, "1086 Count of bytes for the above data"
            unsigned buf, :fcPlcfBklFactoid, 32, "1090 Offset in table stream of smart tag bookmark plc of cpLims[...]"
            unsigned buf, :lcbPlcfBklFactoid, 32, "1094 Count of bytes for the above data"
            unsigned buf, :fcFactoidData, 32, "1098 Offset in table stream of smart tag data This is undocumen[...]"
            unsigned buf, :lcbFactoidData, 32, "1102 Count of bytes for the above data"
            unsigned buf, :fcDocUndo, 32, "1106 Offset in table stream of undocumented undo / versioning d[...]"
            unsigned buf, :lcbDocUndo, 32, "1110 Count of bytes for the above data"
            unsigned buf, :fcSttbfBkmkFcc, 32, "1114 Offset in table stream of fcc bookmark sttb This is intern[...]"
            unsigned buf, :lcbSttbfBkmkFcc, 32, "1118 Count of bytes for the above data"
            unsigned buf, :fcPlcfBkfFcc, 32, "1122 Offset in table stream of fcc bookmark plc of cpFirsts Thi[...]"
            unsigned buf, :lcbPlcfBkfFcc, 32, "1126 Count of bytes for the above data"
            unsigned buf, :fcPlcfBklFcc, 32, "1130 Offset in table stream of fcc bookmark plc of cpLims This [...]"
            unsigned buf, :lcbPlcfBklFcc, 32, "1134 Count of bytes for the above data"
            unsigned buf, :fcSttbfbkmkBPRepairs, 32, "1138 Offset in table stream of file repair bookmark sttb This i[...]"
            unsigned buf, :lcbSttbfbkmkBPRepairs, 32, "1142 Count of bytes for the above data"
            unsigned buf, :fcPlcfbkfBPRepairs, 32, "1146 Offset in table stream of file repair bookmark plc of cpFi[...]"
            unsigned buf, :lcbPlcfbkfBPRepairs, 32, "1150 Count of bytes for the above data"
            unsigned buf, :fcPlcfbklBPRepairs, 32, "1154 Offset in table stream of file repair bookmark plc of cpLi[...]"
            unsigned buf, :lcbPlcfbklBPRepairs, 32, "1158 Count of bytes for the above data"
            unsigned buf, :fcPmsNew, 32, "1162 Offset in table stream of new mail merge state information[...]"
            unsigned buf, :lcbPmsNew, 32, "1166 Count of bytes for the above data"
            unsigned buf, :fcODSO, 32, "1170 Offset in table stream of IMsoODSO/IMsoMailmerge Informati[...]"
            unsigned buf, :lcbODSO, 32, "1174 Count of bytes for the above data"
            unsigned buf, :fcPlcfpmiOldXP, 32, "1178 Offset in table stream of Paragraph Mark Information (Old [...]"
            unsigned buf, :lcbPlcfpmiOldXP, 32, "1182 Count of bytes for the above data ."
            unsigned buf, :fcPlcfpmiNewXP, 32, "1186 Offset in table stream of Paragraph Mark Information (New [...]"
            unsigned buf, :lcbPlcfpmiNewXP, 32, "1190 Count of bytes for the above data."
            unsigned buf, :fcPlcfpmiMixedXP, 32, "1194 Offset in table stream of Paragraph Mark Information (Mixe[...]"
            unsigned buf, :lcbPlcfpmiMixedXP, 32, "1198 Count of bytes for the above data."
            unsigned buf, :fcEncryptedProps, 32, "1202 Offset in table stream of encryption properties This is an[...]"
            unsigned buf, :lcbEncryptedProps, 32, "1206 Count of bytes for the above data"
            unsigned buf, :fcPlcffactoid, 32, "1210 Offset in table stream of background factoid checking stat[...]"
            unsigned buf, :lcbPlcffactoid, 32, "1214 Count of bytes for the above data."
            unsigned buf, :fcPlcflvcOldXP, 32, "1218 Offset in table stream of LVC PLC (Old View) for Word 2002[...]"
            unsigned buf, :lcbPlcflvcOldXP, 32, "1222 Count of bytes for the above data."
            unsigned buf, :fcPlcflvcNewXP, 32, "1226 Offset in table stream of LVC PLC (New View) for Word 2002[...]"
            unsigned buf, :lbcPlcflvcNewXP, 32, "1230 Count of bytes for the above data."
            unsigned buf, :fcPlcflvcMixedXP, 32, "1234 Offset in table stream of LVC PLC (Mixed View) for Word 20[...]"
            unsigned buf, :lcbPlcflvcMixedXP, 32, "1238 Count of bytes for the above data."
            unsigned buf, :fcHplxsdr, 32, "1242 XML Schema Definition References"
            unsigned buf, :lcbHplxsdr, 32, "1246 Count of bytes for the above data."
            unsigned buf, :fcSttbfBkmkSdt, 32, "1250 SDT bookmark STTB"
            unsigned buf, :lcbSttbfBkmkSdt, 32, "1254 Count of bytes for the above data."
            unsigned buf, :fcPlcfBkfSdt, 32, "1258 SDT bookmark plc of cpFirsts"
            unsigned buf, :lcbPlcfBkfSdt, 32, "1262 Count of bytes for the above data."
            unsigned buf, :fcPlcfBklSdt, 32, "1266 SDT bookmark plc of cpLims"
            unsigned buf, :lcbPlcfBklSdt, 32, "1270 Count of bytes for the above data."
            unsigned buf, :fcCustomXForm, 32, "1274 Custom XML Transform on save"
            unsigned buf, :lcbCustomXForm, 32, "1278 Count of bytes for the above data."
            unsigned buf, :fcSttbfBkmkProt, 32, "1282 Range protection bookmark STTB This is undocumented bookma[...]"
            unsigned buf, :lcbSttbfBkmkProt, 32, "1286 Count of bytes for the above data."
            unsigned buf, :fcPlcfBkfProt, 32, "1290 Range protection bookmark plc of cpFirsts This is undocume[...]"
            unsigned buf, :lcbPlcfBkfProt, 32, "1294 Count of bytes for the above data."
            unsigned buf, :fcPlcfBklProt, 32, "1298 Range protection bookmark plc of cpLims This is undocument[...]"
            unsigned buf, :lcbPlcfBklProt, 32, "1302 Count of bytes for the above data."
            unsigned buf, :fcSttbProtUser, 32, "1306 Range protection user list STTB This is undocumented user [...]"
            unsigned buf, :lcbSttbProtUser, 32, "1310 Count of bytes for the above data."
            unsigned buf, :fcPlcftpc, 32, "1314 Current text paragraph cache This is unused."
            unsigned buf, :lcbPlcftpc, 32, "1318 Count of bytes for the above data."
            unsigned buf, :fcPlcfpmiOld, 32, "1322 Paragraph Mark Information (Old View) This is an internal [...]"
            unsigned buf, :lcbPlcfpmiOld, 32, "1326 Count of bytes for the above data."
            unsigned buf, :fcPlcfpmiOldInline, 32, "1330 Paragraph Mark Information (Old Inline View) This is an in[...]"
            unsigned buf, :lcbPlcfpmiOldInline, 32, "1334 Count of bytes for the above data."
            unsigned buf, :fcPlcfpmiNew, 32, "1338 Paragraph Mark Information (New View) This is an internal [...]"
            unsigned buf, :lcbPlcfpmiNew, 32, "1342 Count of bytes for the above data."
            unsigned buf, :fcPlcfpmiNewInline, 32, "1346 Paragraph Mark Information (New Inline View) This is an in[...]"
            unsigned buf, :lcbPlcfpmiNewInline, 32, "1350 Count of bytes for the above data."
            unsigned buf, :fcPlcflvcOld, 32, "1354 LVC PLC (Old View) This is an internal information cache u[...]"
            unsigned buf, :lcbPlcflvcOld, 32, "1358 Count of bytes for the above data."
            unsigned buf, :fcPlcflvcOldInline, 32, "1362 LVC PLC (Old Inline View) This is an internal information [...]"
            unsigned buf, :lcbPlcflvcOldInline, 32, "1366 Count of bytes for the above data."
            unsigned buf, :fcPlcflvcNew, 32, "1370 LVC PLC (New View) This is an internal information cache u[...]"
            unsigned buf, :lcbPlcflvcNew, 32, "1374 Count of bytes for the above data."
            unsigned buf, :fcPlcflvcNewInline, 32, "1378 LVC PLC (New Inline View) This is an internal information [...]"
            unsigned buf, :lcbPlcflvcNewInline, 32, "1382 Count of bytes for the above data."
            unsigned buf, :fcpgdMother, 192, "1386 This is an internal information cache used by Word."
            unsigned buf, :fcpgdFtn, 192, "1410 This is an internal information cache used by Word."
            unsigned buf, :fcpgdEdn, 192, "1434 This is an internal information cache used by Word."
            unsigned buf, :fcAfd, 32, "1458 This is internal revision mark view information used by Wo[...]"
            unsigned buf, :lcbAfd, 32, "1462 Count of bytes for the above data."
            unsigned buf, :cswNew, 16, "1466 The number of entries in rgswNew[]"
            unsigned buf, :nFib, 16, "1468 The actual nFib, moved here because some readers assumed t[...]"
            unsigned buf, :cQuickSavesNew, 16, "1470 Because of the above, we need to use cQuickSaves [...]"
            group :ol, :fcStshfOrig, :lcbStshfOrig
            group :ol, :fcStshf, :lcbStshf
            group :ol, :fcPlcffndRef, :lcbPlcffndRef
            group :ol, :fcPlcffndTxt, :lcbPlcffndTxt
            group :ol, :fcPlcfandRef, :lcbPlcfandRef
            group :ol, :fcPlcfandTxt, :lcbPlcfandTxt
            group :ol, :fcPlcfsed, :lcbPlcfsed
            group :ol, :fcPlcpad, :lcbPlcpad
            group :ol, :fcPlcfphe, :lcbPlcfphe
            group :ol, :fcSttbfglsy, :lcbSttbfglsy
            group :ol, :fcPlcfglsy, :lcbPlcfglsy
            group :ol, :fcPlcfhdd, :lcbPlcfhdd
            group :ol, :fcPlcfbteChpx, :lcbPlcfbteChpx
            group :ol, :fcPlcfbtePapx, :lcbPlcfbtePapx
            group :ol, :fcPlcfsea, :lcbPlcfsea
            group :ol, :fcSttbfffn, :lcbSttbfffn
            group :ol, :fcPlcffldMom, :lcbPlcffldMom
            group :ol, :fcPlcffldHdr, :lcbPlcffldHdr
            group :ol, :fcPlcffldFtn, :lcbPlcffldFtn
            group :ol, :fcPlcffldAtn, :lcbPlcffldAtn
            group :ol, :fcPlcffldMcr, :lcbPlcffldMcr
            group :ol, :fcSttbfbkmk, :lcbSttbfbkmk
            group :ol, :fcPlcfbkf, :lcbPlcfbkf
            group :ol, :fcPlcfbkl, :lcbPlcfbkl
            group :ol, :fcCmds, :lcbCmds
            group :ol, :fcPlcmcr, :lcbPlcmcr
            group :ol, :fcSttbfmcr, :lcbSttbfmcr
            group :ol, :fcPrDrvr, :lcbPrDrvr
            group :ol, :fcPrEnvPort, :lcbPrEnvPort
            group :ol, :fcPrEnvLand, :lcbPrEnvLand
            group :ol, :fcWss, :lcbWss
            group :ol, :fcDop, :lcbDop
            group :ol, :fcSttbfAssoc, :lcbSttbfAssoc
            group :ol, :fcClx, :lcbClx
            group :ol, :fcPlcfpgdFtn, :lcbPlcfpgdFtn
            group :ol, :fcAutosaveSource, :lcbAutosaveSource
            group :ol, :fcGrpXstAtnOwners, :lcbGrpXstAtnOwners
            group :ol, :fcSttbfAtnbkmk, :lcbSttbfAtnbkmk
            group :ol, :fcPlcdoaMom, :lcbPlcdoaMom
            group :ol, :fcPlcdoaHdr, :lcbPlcdoaHdr
            group :ol, :fcPlcspaMom, :lcbPlcspaMom
            group :ol, :fcPlcspaHdr, :lcbPlcspaHdr
            group :ol, :fcPlcfAtnbkf, :lcbPlcfAtnbkf
            group :ol, :fcPlcfAtnbkl, :lcbPlcfAtnbkl
            group :ol, :fcPms, :lcbPms
            group :ol, :fcFormFldSttbs, :lcbFormFldSttbs
            group :ol, :fcPlcfendRef, :lcbPlcfendRef
            group :ol, :fcPlcfendTxt, :lcbPlcfendTxt
            group :ol, :fcPlcffldEdn, :lcbPlcffldEdn
            group :ol, :fcPlcfpgdEdn, :lcbPlcfpgdEdn
            group :ol, :fcDggInfo, :lcbDggInfo
            group :ol, :fcSttbfRMark, :lcbSttbfRMark
            group :ol, :fcSttbCaption, :lcbSttbCaption
            group :ol, :fcSttbAutoCaption, :lcbSttbAutoCaption
            group :ol, :fcPlcfwkb, :lcbPlcfwkb
            group :ol, :fcPlcfspl, :lcbPlcfspl
            group :ol, :fcPlcftxbxTxt, :lcbPlcftxbxTxt
            group :ol, :fcPlcffldTxbx, :lcbPlcffldTxbx
            group :ol, :fcPlcfhdrtxbxTxt, :lcbPlcfhdrtxbxTxt
            group :ol, :fcPlcffldHdrTxbx, :lcbPlcffldHdrTxbx
            group :ol, :fcStwUser, :lcbStwUser
            group :ol, :fcCookieData, :lcbCookieData
            group :ol, :fcSttbfIntlFld, :lcbSttbfIntlFld
            group :ol, :fcRouteSlip, :lcbRouteSlip
            group :ol, :fcSttbSavedBy, :lcbSttbSavedBy
            group :ol, :fcSttbFnm, :lcbSttbFnm
            group :ol, :fcPlcfLst, :lcbPlcfLst
            group :ol, :fcPlfLfo, :lcbPlfLfo
            group :ol, :fcPlcftxbxBkd, :lcbPlcftxbxBkd
            group :ol, :fcPlcftxbxHdrBkd, :lcbPlcftxbxHdrBkd
            group :ol, :fcDocUndoWord9, :lcbDocUndoWord9
            group :ol, :fcRgbuse, :lcbRgbuse
            group :ol, :fcUsp, :lcbUsp
            group :ol, :fcUskf, :lcbUskf
            group :ol, :fcPlcupcRgbuse, :lcbPlcupcRgbuse
            group :ol, :fcPlcupcUsp, :lcbPlcupcUsp
            group :ol, :fcSttbGlsyStyle, :lcbSttbGlsyStyle
            group :ol, :fcPlgosl, :lcbPlgosl
            group :ol, :fcPlcocx, :lcbPlcocx
            group :ol, :fcPlcfbteLvc, :lcbPlcfbteLvc
            group :ol, :fcPlcflvcPre10, :lcbPlcflvcPre10
            group :ol, :fcPlcasumy, :lcbPlcasumy
            group :ol, :fcPlcfgram, :lcbPlcfgram
            group :ol, :fcSttbListNames, :lcbSttbListNames
            group :ol, :fcSttbfUssr, :lcbSttbfUssr
            group :ol, :fcPlcfTch, :lcbPlcfTch
            group :ol, :fcRmdfThreading, :lcbRmdfThreading
            group :ol, :fcMid, :lcbMid
            group :ol, :fcSttbRgtplc, :lcbSttbRgtplc
            group :ol, :fcMsoEnvelope, :lcbMsoEnvelope
            group :ol, :fcPlcflad, :lcbPlcflad
            group :ol, :fcRgdofr, :lcbRgdofr
            group :ol, :fcPlcosl, :lcbPlcosl
            group :ol, :fcPlcfcookieOld, :lcbPlcfcookieOld
            group :ol, :fcUnused, :lcbUnused
            group :ol, :fcPlcfpgp, :lcbPlcfpgp
            group :ol, :fcPlcfuim, :lcbPlcfium
            group :ol, :fcPlfguidUim, :lcbPlfguidUim
            group :ol, :fcAtrdExtra, :lcbAtrdExtra
            group :ol, :fcPlrsid, :lcbPlrsid
            group :ol, :fcSttbfBkmkFactoid, :lcbSttbfBkmkFactoid
            group :ol, :fcPlcfBkfFactoid, :lcbPlcfBkfFactoid
            group :ol, :fcPlcfcookie, :lcbPlcfcookie
            group :ol, :fcPlcfBklFactoid, :lcbPlcfBklFactoid
            group :ol, :fcFactoidData, :lcbFactoidData
            group :ol, :fcDocUndo, :lcbDocUndo
            group :ol, :fcSttbfBkmkFcc, :lcbSttbfBkmkFcc
            group :ol, :fcPlcfBkfFcc, :lcbPlcfBkfFcc
            group :ol, :fcPlcfBklFcc, :lcbPlcfBklFcc
            group :ol, :fcSttbfbkmkBPRepairs, :lcbSttbfbkmkBPRepairs
            group :ol, :fcPlcfbkfBPRepairs, :lcbPlcfbkfBPRepairs
            group :ol, :fcPlcfbklBPRepairs, :lcbPlcfbklBPRepairs
            group :ol, :fcPmsNew, :lcbPmsNew
            group :ol, :fcODSO, :lcbODSO
            group :ol, :fcPlcfpmiOldXP, :lcbPlcfpmiOldXP
            group :ol, :fcPlcfpmiNewXP, :lcbPlcfpmiNewXP
            group :ol, :fcPlcfpmiMixedXP, :lcbPlcfpmiMixedXP
            group :ol, :fcEncryptedProps, :lcbEncryptedProps
            group :ol, :fcPlcffactoid, :lcbPlcffactoid
            group :ol, :fcPlcflvcOldXP, :lcbPlcflvcOldXP
            group :ol, :fcPlcflvcMixedXP, :lcbPlcflvcMixedXP
            group :ol, :fcHplxsdr, :lcbHplxsdr;
            group :ol, :fcSttbfBkmkSdt, :lcbSttbfBkmkSdt
            group :ol, :fcPlcfBkfSdt, :lcbPlcfBkfSdt
            group :ol, :fcPlcfBklSdt, :lcbPlcfBklSdt
            group :ol, :fcCustomXForm, :lcbCustomXForm
            group :ol, :fcSttbfBkmkProt, :lcbSttbfBkmkProt
            group :ol, :fcPlcfBkfProt, :lcbPlcfBkfProt
            group :ol, :fcPlcfBklProt, :lcbPlcfBklProt
            group :ol, :fcSttbProtUser, :lcbSttbProtUser
            group :ol, :fcPlcftpc, :lcbPlcftpc
            group :ol, :fcPlcfpmiOld, :lcbPlcfpmiOld
            group :ol, :fcPlcfpmiOldInline, :lcbPlcfpmiOldInline
            group :ol, :fcPlcfpmiNew, :lcbPlcfpmiNew
            group :ol, :fcPlcfpmiNewInline, :lcbPlcfpmiNewInline
            group :ol, :fcPlcflvcOld, :lcbPlcflvcOld
            group :ol, :fcPlcflvcOldInline, :lcbPlcflvcOldInline
            group :ol, :fcPlcflvcNew, :lcbPlcflvcNew
            group :ol, :fcPlcflvcNewInline, :lcbPlcflvcNewInline
            group :ol, :fcAfd, :lcbAfd
        }
    end

end #WordStructures
