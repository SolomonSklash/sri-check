"""
Name:           SRI Check
Version:        2.0.0
Date:           08/17/2018
Author:         bellma101 - bellma101@0xfeed.io - Penetration Tester with FIS Global
Gitlab:         https://github.com/bellma101/cookie-decrypter/
Description:    This extension detects the lack of Subresource Integrity attributes
in <script> and <link> tags.
Copyright (c) 2018 bellma101
"""

try:
    from burp import IBurpExtender, IScannerCheck, IScanIssue
    from java.lang import RuntimeException
    from java.io import PrintWriter
    from array import array
    import re
    import sys
    import string
except ImportError:
    print "Failed to load dependencies."

VERSION = '0.0.1'

# Inherit IBurpExtender as base class, which defines registerExtenderCallbacks
# Inherit IScannerCheck to register as custom scanner


class BurpExtender(IBurpExtender, IScannerCheck):

    # get references to callbacks, called when extension is loaded
    def registerExtenderCallbacks(self, callbacks):

        # get a local instance of callbacks object
        self._callbacks = callbacks
        self._callbacks.setExtensionName("SRI Check")
        self._helpers = self._callbacks.getHelpers()

        # register as scanner object so we get used for active/passive scans
        self._callbacks.registerScannerCheck(self)

        stdout = PrintWriter(callbacks.getStdout(), True)
        stdout.println("""Successfully loaded SRI Checks v""" + VERSION + """\n
Repository @ https://github.com/bellma101/sri-check
Send feedback or bug reports to bellma101@0xfeed.io
Copyright (c) 2018 bellma101""")

        return

    # See https://github.com/PortSwigger/example-scanner-checks/blob/master/python/CustomScannerChecks.py
    def _get_matches(self, response, match):
        matches = []
        start = 0
        reslen = len(response)
        matchlen = len(match)
        while start < reslen:
            start = self._helpers.indexOf(response, match, True, start, reslen)
            if start == -1:
                break
            matches.append(array('i', [start, start + matchlen]))
            start += matchlen

        return matches

    # Parse response for <script> and <link> tags
    def regexResponseParse(self):
        matches = []
        scriptRegex = r"\<script.+\>\<\/script\>"
        linkRegex = r"\<link.+\>"

        try:
            compiledScriptRegex = re.compile(scriptRegex)
            compiledLinkRegex = re.compile(linkRegex)
        except:
            print("Failed to compile regexes.")

        try:
            response = self._requestResponse.getResponse()
        except:
            print("Failed to get response.")

        try:
            scriptMatch = compiledScriptRegex.findall(self._helpers.bytesToString(response))
            linkMatch = compiledLinkRegex.findall(self._helpers.bytesToString(response))
        except:
            print("Failed to run regexes.")

        try:
            for match in scriptMatch:
                matches.append(match)
            for match in linkMatch:
                matches.append(match)
        except:
            print("Failed to iterate through matches.")

        return matches

    # 'The Scanner invokes this method for each base request/response that is
    # passively scanned'
    # passing the self object as well for access to helper functions, etc.
    # java.util.List<IScanIssue> doPassiveScan(IHttpRequestResponse
    # baseRequestResponse)
    def doPassiveScan(self, baseRequestResponse):

        self._requestResponse = baseRequestResponse

        issues = list()

        # Analyze response for Host header - DO I NEED THIS???????????**********************
        # try:
        #     analyzedResponse = self._helpers.analyzeResponse(
        #         baseRequestResponse.getResponse())
        #     headerList = analyzedResponse.getHeaders()

        # except:
        #     print 'Failed to parse reponse headers.'

        # Analyze request for Host header
        try:
            analyzedRequest = self._helpers.analyzeRequest(
                baseRequestResponse.getRequest())
            headerRequestList = analyzedRequest.getHeaders()

            for header in headerRequestList:
                try:
                    if "Host" in header:
                        hostHeader = header
                        domain = hostHeader.split()[1]
                except:
                        print("Failed to get Host header.")

        except:
            print 'Failed to parse request headers.'

        # Get <script> and <link> tags via regex
        try:
            matches = self.regexResponseParse()
        except:
            print("Failed to get regex matches.")

        # COMMENT NEEDED HERE
        try:
            for match in matches:
                try:
                    if domain.lower() not in match.lower():
                        integrityRegex = r"""integrity=('|")sha(256|384|512)-[a-zA-Z0-9\/=+]+('|")"""
                        compiledIntegrityRegex = re.compile(integrityRegex)                    

                        result = compiledIntegrityRegex.search(match)
                        if result is None:
                            print("RAISE ISSUE HERE!")
                            # Add issues here
                except:
                    print("Failed to match against domain.")
        except:
            print("Failed to print matches.")

        if len(issues) > 0:
            return issues

        return None

    # 'The Scanner invokes this method when the custom Scanner check has
    # reported multiple issues for the same URL path'
    # 'The method should return -1 to report the existing issue only, 0 to
    # report both issues, and 1 to report the new issue only.'
    # consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()):
            return -1
        else:
            return 0

# 'This interface is used to retrieve details of Scanner issues. Extensions
# can obtain details of issues by registering an IScannerListener or
# by calling IBurpExtenderCallbacks.getScanIssues(). Extensions can also add
# custom Scanner issues by registering an IScannerCheck or calling
# IBurpExtenderCallbacks.addScanIssue(), and providing their own
# implementations of this interface. Note that issue descriptions and other
# text generated by extensions are subject to an HTML whitelist that allows
# only formatting tags and simple hyperlinks.'
# Here we are implementing our own custom scan issue to set scan issue
# information parameters and creating getters for each parameter


class SRIScanIssue(IScanIssue):
    # constructor for setting issue information
    def __init__(self, httpService, url, requestResponse, decodedCookie,
                 cookieName, rawCookieValue):
        self._httpService = httpService
        self._url = url
        self._requestResponse = requestResponse
        self._cookieName = cookieName
        self._rawCookieValue = rawCookieValue
        self._decodedCookie = decodedCookie

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return 'Decrypted Netscaler Persistence Cookie'

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return 'Information'

    def getConfidence(self):
        return 'Certain'

    def getIssueBackground(self):
        return 'Citrix Netscaler persistence cookies use weak encryption, ' \
            'including a Caesar shift and XORing against fixed values.' \
            'These cookies are trivially decrypted and reveal the server ' \
            'name, IP address, and port.'

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        splitCookie = self._decodedCookie.split(':')
        description = 'A Netscaler persistence cookie was found and decrypted.<br>'
        description += '<br><b>Encrypted Cookie Value: </b>' + str(self._rawCookieValue)
        description += '<br><br><b>Decrypted values:</b>'
        description += '<br><ul><li><b>Server Name: </b>' + str(splitCookie[0])
        description += '</li><li><b>Server IP: </b>' + splitCookie[1]
        description += '</li><li><b>Server Port: </b>' + splitCookie[2] + '</li></ul>'
        return description

    def getRemediationDetail(self):
        return '<ul><li>https://www.citrix.com/blogs/2011/08/05/' \
            'secure-your-application-cookies-before-it-is-too-late/' \
            '</li><li>https://docs.citrix.com/en-us/netscaler/11/' \
            'traffic-management/load-balancing/load-balancing-' \
            'persistence/http-cookie-persistence.html</li></ul>'

    def getHttpMessages(self):
        return self._requestResponse

    def getHttpService(self):
        return self._httpService
