"""
Name:           SRI Check
Version:        1.0.4
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
except ImportError:
    print "Failed to load dependencies."

VERSION = '1.0.4'

# Pre-compile regexes
scriptRegex = r"\<script.*?\>\<\/script\>"
linkRegex = r"\<link.*?\>"
integrityRegex = r"""integrity=('|")sha(256|384|512)-[a-zA-Z0-9\/=+]+('|")"""
relativePathRegex = r"=('|\")(https|http|//)"

try:
    compiledScriptRegex = re.compile(scriptRegex)
    compiledLinkRegex = re.compile(linkRegex)
    compiledIntegrityRegex = re.compile(integrityRegex)
    compiledRelativePathRegex = re.compile(relativePathRegex)    
except:
    print("Failed to compile regexes.")

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

        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        self._stdout.println("""Successfully loaded SRI Checks v""" + VERSION + """\n
Repository @ https://github.com/bellma101/sri-check
Send feedback or bug reports to bellma101@0xfeed.io
Copyright (c) 2018 bellma101""")

        return

    # Get matches for highlighting locations in responses
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

        try:
            response = self._requestResponse.getResponse()
        except:
            self._stderr.println("Failed to get response.")

        try:
            scriptMatch = compiledScriptRegex.findall(self._helpers.bytesToString(response))
            linkMatch = compiledLinkRegex.findall(self._helpers.bytesToString(response))
        except:
            self._stderr.println("Failed to run regexes.")

        try:
            for match in scriptMatch:
                matches.append(match)
            for match in linkMatch:
                matches.append(match)
        except:
            self._stderr.println("Failed to iterate through matches.")

        return matches

    # 'The Scanner invokes this method for each base request/response that is
    # passively scanned'
    # passing the self object as well for access to helper functions, etc.
    # java.util.List<IScanIssue> doPassiveScan(IHttpRequestResponse
    # baseRequestResponse)

    def doPassiveScan(self, baseRequestResponse):

        self._requestResponse = baseRequestResponse

        issues = list()

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
                        self._stderr.println("Failed to get Host header.")

        except:
            self._stderr.println("Failed to parse request headers.")

        # Get <script> and <link> tags via regex
        try:
            matches = self.regexResponseParse()
        except:
            self._stderr.println("Failed to get regex matches.")

        # Parse matches for missing SRI attribute and create corresponding issue
        try:
            for match in matches:
                try:  # check if resource is being loaded from 3rd party
                    if domain.lower() not in match.lower():
                        thirdPartyResult = compiledIntegrityRegex.search(match)

                        # check for relative paths, i.e. no http/https
                        relativePathResult = compiledRelativePathRegex.search(match)

                        # process 3rd party resources
                        if thirdPartyResult is None and relativePathResult is not None:

                            # Get offsets for highlighting response in issue detail
                            try:
                                offset = self._get_matches(baseRequestResponse.getResponse(), match)
                            except:
                                self._stderr.println("Failed to get match offset.")
                            # Append new issues
                            try:
                                issues.append(SRIScanIssue(
                                    self._requestResponse.getHttpService(),
                                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                    [self._callbacks.applyMarkers(self._requestResponse, None, offset)]
                                ))
                            except:
                                self._stderr.println("Failed to append issue.")
                except:
                    self._stderr.println("Failed to match against domain.")
        except:
            self._stderr.println("Failed to print matches.")

        if len(issues) > 0:
            return issues

        return None

    # 'The Scanner invokes this method when the custom Scanner check has
    # reported multiple issues for the same URL path'
    # 'The method should return -1 to report the existing issue only, 0 to
    # report both issues, and 1 to report the new issue only.'
    # consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
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
    def __init__(self, httpService, url, requestResponse):
        self._httpService = httpService
        self._url = url
        self._requestResponse = requestResponse

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return 'Missing Subresource Integrity Attribute'

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return 'Information'

    def getConfidence(self):
        return 'Firm'

    def getIssueBackground(self):
        return """Third-party libraries and scripts, such as Bootstrap, Angular, and jQuery,are commonly included from remote, potentially untrusted servers and CDNs. Subresource Integrity is a mechanism that verifys each time a resource is fetched, it matches a known good version and has not been tampered with. If Subresource Integrity has not been implemented, attackers could make malicious changes to a remote resource and compromise any site that includes the resource, as well as any users of the affected site."""

    def getRemediationBackground(self):
        return "https://scotthelme.co.uk/subresource-integrity/<br>" \
                "https://report-uri.com/home/sri_hash<br>" \
                "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity<br>" \
                "https://www.w3.org/TR/SRI/"

    def getIssueDetail(self):
        description = "A script or stylesheet is missing the Subresource Integrity attribute."
        return description

    def getRemediationDetail(self):
        return """Subresource Integrity should be used any time scripts or stylesheets are fetched from a third-party source. The "integrity" attribute is included any time a <script> or <link> HTML tag are used, e.g. <script src="https://example.com/example-framework.js" integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" crossorigin="anonymous"></script> The "crossorigin" attribute is included to indicate that no credentials are needed in order fetch the resource.
In order to generate the hash of the requested file, the following Linux command can be used on the resource file: "shasum -b -a [256,384,512] FILENAME.js | xxd -r -p | base64". In addition, two Content Security Policy header directives can be used to enforce the use of SRI on scripts and stylesheets: "require-sri-for script" and "require-sri-for style"."""

    def getHttpMessages(self):
        return self._requestResponse

    def getHttpService(self):
        return self._httpService
