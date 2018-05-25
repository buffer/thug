import logging

from thug.Logging.SampleLogging import SampleLogging

log = logging.getLogger("Thug")
sample_logging = SampleLogging()


class TestSampleLogging:
    def test_get_none(self):
        assert not sample_logging.get_sample_type("")

    def test_get_pe(self):
        pe_path   = "../test_files/hello.exe"
        file_type = sample_logging.get_sample_type(open(pe_path).read())
        assert file_type in ('PE', )

    def test_get_pdf(self):
        pdf_path  = "../test_files/pdf.pdf"
        file_type = sample_logging.get_sample_type(open(pdf_path).read(1024))
        assert file_type in ('PDF', )

    def test_get_jar(self):
        jar_path  = "../test_files/hello.jar"
        file_type = sample_logging.get_sample_type(open(jar_path).read())
        assert file_type in ('JAR', )

    def test_get_swf(self):
        swf_path  = "../test_files/swf.swf"
        file_type = sample_logging.get_sample_type(open(swf_path).read())
        assert file_type in ('SWF', )

    def test_get_doc(self):
        doc_path  = "../test_files/doc.doc"
        file_type = sample_logging.get_sample_type(open(doc_path).read())
        assert file_type in ('DOC', )

    def test_get_rtf(self):
        rtf_path  = "../test_files/rtf.rtf"
        file_type = sample_logging.get_sample_type(open(rtf_path).read())
        assert file_type in ('RTF', )

    def test_get_imphash(self):
        pe_path = "../test_files/hello.exe"
        imphash = sample_logging.get_imphash(open(pe_path).read())
        assert imphash in ('5ef204cfbc53779500a050c36dea14fc', )

    def test_build_sample(self):
        pe_path = "../test_files/hello.exe"
        data     = open(pe_path).read()
        build = sample_logging.build_sample(data=data, url=pe_path, sampletype='PE')
        assert build

        build = sample_logging.build_sample(data=data, url=pe_path)
        assert build

        build = sample_logging.build_sample(data="")
        assert not build

        build = sample_logging.build_sample(data="not_valid")
        assert not build
