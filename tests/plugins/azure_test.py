import pytest

from detect_secrets.plugins.azure import AzureDetector

class TestAzureDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('DefaultEndpointsProtocol=http;AccountName=account1;AccountKey=Abc1deF23gHIjkLmnOpQRStuVwxYZAB4CDeFG56hIJK7LMnoPq8RSTuVw9x0yz/A1BCDEFGhi/JKLMnopqRSTu==;', 1),
            ('BlobEndpoint=https://blobstoragewebsiteso.blob.core.windows.net/;SharedAccessSignature=sv=2019-12-12&ss=bfqt&srt=c&sp=rwdlacupx&se=2020-11-12T18:35:10Z&st=2020-11-12T10:35:10Z&spr=https&sig=Ab%1CDeFGHIjKlmNoPqRs2tUVwXYZAbcD3eFGhI4jk5lM%6N', 2),
            ('sv=2019-12-12&ss=bfqt&srt=c&sp=rwdlacupx&se=2020-11-12T18:35:10Z&st=2020-11-12T10:35:10Z&spr=https&sig=Ab%1CDeFGHIjKlmNoPqRs2tUVwXYZAbcD3eFGhI4jk5lM%6N', 1),
            ('InstrumentationKey=1234ab56-78cd-9e90-f1ab-12345c6f89af;IngestionEndpoint=https://westeurope-1.in.applicationinsights.azure.com/', 1),
        ],
    )
    def test_analyze_line(self, payload, should_flag):
        logic = AzureDetector()

        output = logic.analyze_line(payload, 1, 'mock_filename')
        assert len(output) == int(should_flag)
