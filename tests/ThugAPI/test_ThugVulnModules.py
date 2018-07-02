from thug.ThugAPI.ThugVulnModules import ThugVulnModules


class TestThugVulnModules:
    vuln_modules = ThugVulnModules()

    def test_invalid_version(self):
        assert not self.vuln_modules.invalid_version('1.6.0.32')
        assert not self.vuln_modules.invalid_version('1')
        assert self.vuln_modules.invalid_version('1.6.A.32')

    # Acropdf
    def test_acropdf(self):
        acropdf_version = self.vuln_modules.acropdf_pdf
        assert acropdf_version in ('9.1.0', )

        self.vuln_modules.acropdf_pdf = '1.0.0'
        acropdf_version = self.vuln_modules.acropdf  # Testing the 'acropdf' property
        assert acropdf_version in ('1.0.0', )

    def test_warning_acropdf(self, caplog):
        caplog.clear()

        self.vuln_modules.acropdf_pdf = '1.0.A'
        assert '[WARNING] Invalid Adobe Acrobat Reader version provided' in caplog.text

    def test_disable_acropdf(self):
        self.vuln_modules.disable_acropdf()
        assert self.vuln_modules.acropdf_disabled

    # Shockwave-flash
    def test_shockwave_flash(self):
        shockwave_version = self.vuln_modules.shockwave_flash
        assert shockwave_version in ('10.0.64.0', )

        self.vuln_modules.shockwave_flash = '8.0'
        shockwave_version = self.vuln_modules.shockwave_flash
        assert shockwave_version in ('8.0', )

    def test_warning_shockwave_flash(self, caplog):
        caplog.clear()

        self.vuln_modules.shockwave_flash = '1.0'
        assert '[WARNING] Invalid Shockwave Flash version provided' in caplog.text

    def test_disable_shockwave_flash(self):
        self.vuln_modules.disable_shockwave_flash()
        assert self.vuln_modules.shockwave_flash_disabled

    # Java
    def test_javaplugin(self):
        javaplugin_version = self.vuln_modules.javaplugin
        assert javaplugin_version in ('160_32', )

        self.vuln_modules.javaplugin = '1.0'
        javaplugin_version = self.vuln_modules.javaplugin
        assert javaplugin_version in ('100_00', )

    def test_warning_javaplugin(self, caplog):
        caplog.clear()

        self.vuln_modules.javaplugin = '1.A'
        assert '[WARNING] Invalid JavaPlugin version provided' in caplog.text

    def test_disable_javaplugin(self):
        self.vuln_modules.disable_javaplugin()
        assert self.vuln_modules.javaplugin_disabled

    def test_javawebstart_isinstalled(self):
        version = self.vuln_modules.javawebstart_isinstalled
        assert version in ('1.0.0.0', )

    # Silverlight
    def test_silverlight(self):
        silverlight_version = self.vuln_modules.silverlight
        assert silverlight_version in ('4.0.50826.0', )

        self.vuln_modules.silverlight = '1.0'
        silverlight_version = self.vuln_modules.silverlight
        assert silverlight_version in ('1.0', )

    def test_warning_silverlight(self, caplog):
        caplog.clear()

        self.vuln_modules.silverlight = '6.0'
        assert '[WARNING] Invalid Silverlight version provided' in caplog.text

    def test_disable_silverlight(self):
        self.vuln_modules.disable_silverlight()
        assert self.vuln_modules.silverlight_disabled
