
#
# HTTP Traceroute using Max-Forwards
# Used to detect reverse-proxies
# version 0.4
#
# by Nicolas Gregoire
# @Agarri_FR // nicolas.gregoire@agarri.fr
#

# imports specific to Burp
from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IScanIssue
from burp import IHttpService
from burp import IHttpRequestResponse

# other imports
import array
import re
import cgi
from java.io import PrintWriter
from javax.swing import JMenuItem
from threading import Thread

class BurpExtender(IBurpExtender, IContextMenuFactory):

	#
	# implement IBurpExtender
	#

	def registerExtenderCallbacks(self, callbacks):

		# properties
		self._title = "Detect reverse-proxies"
        
		# set our extension name
		callbacks.setExtensionName(self._title)

		# keep a reference to our callbacks object
		self._callbacks = callbacks

		# obtain an extension helpers object
		self._helpers = callbacks.getHelpers()
	
		# obtain std streams
		self._stdout = PrintWriter(callbacks.getStdout(), True)
		self._stderr = PrintWriter(callbacks.getStderr(), True)

		# register ourselves as a ContextMenuFactory
		callbacks.registerContextMenuFactory(self)

		return

	#
	# implement IContextMenuFactory
	#

	def createMenuItems(self, invocation):

		# modify a few menus
		if (invocation.getInvocationContext() == invocation.CONTEXT_TARGET_SITE_MAP_TABLE         \
			or invocation.getInvocationContext() == invocation.CONTEXT_PROXY_HISTORY          \
			or invocation.getInvocationContext() == invocation.CONTEXT_TARGET_SITE_MAP_TREE   \
			or invocation.getInvocationContext() == invocation.CONTEXT_MESSAGE_VIEWER_REQUEST \
			or invocation.getInvocationContext() == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST):

			# our action will need to access the selected messages
			self._messages = invocation.getSelectedMessages()

			# add a new item executing our action
			item = JMenuItem(self._title, actionPerformed=lambda x, inv=invocation: self.startScanThread(inv))
			
			return [ item ]
		
		return []

	#
	# send to a dedicated thread
	#

	def startScanThread(self, inv):

		Thread(target=lambda: self.httpTraceroute(inv)).start()
		return

	#
	# the core feature
	#

	def httpTraceroute(self, invocation):

		# for each selected message
		for message in invocation.getSelectedMessages():

			# do not process unrequested messages
			if message.getResponse() is None:
				self._stdout.println("[!] Unrequested message, skipping")
				continue

			# parse the request
			parsed_request = self._helpers.analyzeRequest(message)

			# print the URL
			self._stdout.println("[=] Testing %s" % str(parsed_request.getUrl()))

			# test with both TRACE, OPTIONS and the current method
			methods = [ "TRACE", "OPTIONS" ]
			if parsed_request.getMethod() not in methods:
				methods.insert(0, parsed_request.getMethod())
			
			# for each selected method
			for method in methods:

				# update the method
				new_headers = []
				for header in parsed_request.getHeaders():
					if parsed_request.getMethod() in header:
						new_headers.append(header.replace(parsed_request.getMethod(), method))
					else:
						new_headers.append(header)

				# fetch a (fresh) baseline response
				base_body = message.getRequest()[parsed_request.getBodyOffset():]
				base_request = self._helpers.buildHttpMessage(new_headers, base_body)
				base_response = self._callbacks.makeHttpRequest(message.getHttpService(), base_request)
			
				# add the Max-Forwards header
				ttl_headers = new_headers + [ "Max-Forwards: 0" ]
		
				# build and send a new request
				ttl_request = self._helpers.buildHttpMessage(ttl_headers, base_body)
				ttl_response = self._callbacks.makeHttpRequest(message.getHttpService(), ttl_request)

				# compare this response to the baseline
				self.compare_responses(method, base_response, ttl_response)

		return

	#
	# compare two responses
	# 	msg1 is the response to the baseline request
	# 	msg2 is the response to a traceroute request
	#

	def compare_responses(self, method, msg1, msg2):

		# will contain our findings
		findings = []

		# parse messages
		parsed1 = self._helpers.analyzeResponse(msg1.getResponse())
		parsed2 = self._helpers.analyzeResponse(msg2.getResponse())

		# convert lists of headers to dictionaries
		headers1 = self.headers_to_dict(parsed1.getHeaders())
		headers2 = self.headers_to_dict(parsed2.getHeaders())

		# get the bodies
		body1 = msg1.getResponse()[parsed1.getBodyOffset():].tostring()
		body2 = msg2.getResponse()[parsed2.getBodyOffset():].tostring()

		# compare status codes
		if (msg1.getStatusCode() != msg2.getStatusCode()):
			findings.append("<b>Status codes</b> are different<ul><li>Baseline: %d</li><li>Modified: %d</li></ul>" % (msg1.getStatusCode(), msg2.getStatusCode()))

		# compare headers
		checks = [ "Server", "Content-Type", "Via", "X-Via", "X-Forwarded-For", "Set-Cookie" ]
		for c in checks:
			# header found in neither responses
			if (not c in headers1) and (not c in headers2):
				continue
			# header found only in the baseline
			if (not c in headers2) and (c in headers1):
				findings.append("Header <b>%s</b> not present in traceroute response:<ul><li>Value in original response: %s</li></ul>" % (c, headers1[c]))
			# header found only in the traceroute response
			if (not c in headers1) and (c in headers2):
				findings.append("Header <b>%s</b> not present in baseline response:<ul><li>Value in traceroute response: %s</li></ul>" % (c, headers2[c]))
			# header found in both but values are different
			if (c in headers1) and (c in headers2) and (headers1[c] != headers2[c]):
				# do not compare cookies (false positive on session cookies)
				if c != "Set-Cookie":
					findings.append("Header <b>%s</b> have different values:<ul><li>Baseline: %s</li><li>Modified: %s</li></ul>" % (c, headers1[c], headers2[c]))

		# compare bodies
		patterns = [ "<title>(.*)</title>", "<address>(.*)</address>", "Reason: <strong>(.*)</strong>", "X-Forwarded-For: (.*)" ]
		for pattern in patterns:
			# Case insensitive search
			value1 = re.search(pattern, body1, re.IGNORECASE)
			value2 = re.search(pattern, body2, re.IGNORECASE)
                	# string found in neither responses
			if (value1 == None) and (value2 == None):
				continue
			# string found only in the baseline
			if (value2 == None) and (value1 != None):
				# extract only the 1st group, without newlines
				x1 =  value1.groups()[0].strip('\r\n')
				findings.append("String <b>%s</b> not present in traceroute response:<ul><li>Value in baseline response: %s</li></ul>" % (cgi.escape(pattern), x1))
			# string found only in the traceroute response
			if (value1 == None) and (value2 != None):
				# extract only the 1st group, without newlines
				x2 =  value2.groups()[0].strip('\r\n')
				findings.append("String <b>%s</b> not present in baseline response:<ul><li>Value in traceroute response: %s</li></ul>" % (cgi.escape(pattern), x2))
			# string found in both
			if (value1 != None) and (value2 != None):
				# extract only the 1st group, without newlines
				x1 =  value1.groups()[0].strip('\r\n')
				x2 =  value2.groups()[0].strip('\r\n')
				# string found in both but values are different
				if (x1 != x2):
					findings.append("String <b>%s</b> have different values:<ul><li>Baseline: %s</li><li>Modified: %s</li></ul>" % (cgi.escape(pattern), x1, x2))

		# if needed, log the issue
		if findings:
			self._stdout.println("[+] A reverse-proxy was detected using %s, logging the issue" % method)
			issue = ScanIssue(self, method, msg1, msg2, findings)
			self._callbacks.addScanIssue(issue)

		return

	#
	# convert a list of headers to a dictionary
	# key and value are separated by ': '
	#

	def headers_to_dict(self, headers):

		d = {}
		for h in headers:
			try:
				# split
				(k, v) = h.split(': ')
			except ValueError:
				# self._stderr.println("[!] No ': ' in header [%s]" % h)
				continue
			else:
				# add
				if k in d:
					# duplicate key => append
					d[k] = d[k] + " ### " + v
				else:
					# new key
					d[k] = v
		return d

# 
# class implementing IScanIssue
#

class ScanIssue(IScanIssue):

	def __init__(self, extender, method, base_message, modified_message, findings):

		# get its own reference to stdout
		self._stdout = extender._stdout

		# will propose a "compare responses" button when viewing the results
		self._messages = [ base_message, modified_message ]

		# basic information
		self._severity = "Information"
		self._confidence = "Certain"
		self._issueName = "Reverse-proxy detected using %s" % method
		self._issueType = 6296666 # Arbitrary chosen

		# issueBackground
		self._issueBackground = """The traceroute-like HTTP scan uses the "Max-Forwards" header. This header was defined in section 14.31 of RFC 2616.
Quoting the RFC: "The Max-Forwards value is a decimal integer indicating the remaining number of times this request message may be forwarded."
Setting the value of this header to zero will instruct RFC-compliant reverse-proxies to reveal themselves.
The page at http://www.agarri.fr/kom/archives/2011/11/12/traceroute-like_http_scanner/index.html includes some additional information.
You may want to test values like "1" and "2" in order to detect additional reverse-proxies."""

		# construct issueDetail
		str_findings = ""
		for i in findings:
			str_findings = str_findings + ("<li>%s</li>" % i)
		top = "A reverse-proxy was detected. The following heuristics were triggered using 'Max-Fowards: 0':"
		self._issueDetail = top + "<ul>" + str_findings + "</ul>"

		return

	#
	# implement IScanIssue
	#

	def getIssueName(self):
		return self._issueName

	def getIssueType(self):
		return self._issueType

	def getConfidence(self):
		return self._confidence 

	def getHttpMessages(self):
		return self._messages

	def getHttpService(self):
		return self._messages[0].getHttpService()

	def getIssueBackground(self):
		return self._issueBackground

	def getIssueDetail(self):
		return self._issueDetail 

	def getSeverity(self):
		return self._severity

	def getUrl(self):
		return self._messages[0].getUrl()

	def getRemediationBackground(self):
		return None

	def getRemediationDetail(self):
		return None

