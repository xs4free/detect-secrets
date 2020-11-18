"""
This plugin searches for Azure keys
"""

import re

from detect_secrets.plugins.base import RegexBasedDetector

class AzureDetector(RegexBasedDetector):
    """Scans for Azure keys."""
    secret_type = 'Azure key'

    denylist = [
        re.compile(r'accountkey', re.IGNORECASE), #DefaultEndpointsProtocol=http;AccountName=account1;AccountKey=Abc1deF23gHIjkLmnOpQRStuVwxYZAB4CDeFG56hIJK7LMnoPq8RSTuVw9x0yz/A1BCDEFGhi/JKLMnopqRSTu==;
        re.compile(r'sharedaccesskey', re.IGNORECASE), #Endpoint=sb://test.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=AB1C2DeFGHIJ3KLmNOpQrst4uVWXYZaBCDefghijKlm=
        re.compile(r'sharedaccesssignature', re.IGNORECASE), #BlobEndpoint=https://blobstoragewebsiteso.blob.core.windows.net/;SharedAccessSignature=sv=2019-12-12&ss=bfqt&srt=c&sp=rwdlacupx&se=2020-11-12T18:35:10Z&st=2020-11-12T10:35:10Z&spr=https&sig=Ab%1CDeFGHIjKlmNoPqRs2tUVwXYZAbcD3eFGhI4jk5lM%6N
        re.compile(r'sig=', re.IGNORECASE), #SAS-token BlobStorage #example: sv=2019-12-12&ss=bfqt&srt=c&sp=rwdlacupx&se=2020-11-12T18:35:10Z&st=2020-11-12T10:35:10Z&spr=https&sig=Ab%1CDeFGHIjKlmNoPqRs2tUVwXYZAbcD3eFGhI4jk5lM%6N
        re.compile(r'instrumentationkey', re.IGNORECASE), #InstrumentationKey=1234ab56-78cd-9e90-f1ab-12345c6f89af;IngestionEndpoint=https://westeurope-1.in.applicationinsights.azure.com/
    ]
