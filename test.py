# coding=utf8
# the above tag defines encoding for this document and is for Python 2.x compatibility

import re

response = """
<!doctype html>

<html lang="en">

<head>
  <meta charset="utf-8">
  <title>Testing</title>
  <meta name="description" content="Tests for burp-sri">
  <meta name="author" content="bellma101">
</head>

<body>
  <p> Some stuff here</p>
    <script src="https://example.com/example-framework.js" integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" crossorigin="anonymous"></script>
    
    <script src="https://localhost:8002/asd" integrity="sha384-OGQ1Nzc3ODYxMDk2ZTM1MzIzOWVhN2IzN2M0NTY5OWYzYjQzODVmNWJiMjU1M2NiZTFhNzgzMzNiZDJhODJjYWY3ODg5Yjg2NDIwYTUwZjUwZTI4NmVjN2ZhZDU1NzcxCg==" crossorigin="anonymous"></script>
    
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.4/css/bootstrap.min.css" integrity="sha256-8EtRe6XWoFEEhWiaPkLawAD1FkD9cbmGgEy6F46uQqU= sha512-/5KWJw2mvMO2ZM5fndVxUQmpVPqaxZyYRTMrXtrprsyQ2zM0o0NMjU02I8ZJXeBP trmrPO4IAyCCRsydG0BJoQ==" crossorigin="anonymous">
    
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/2.1.3/jquery.min.js"></script>

    <link rel="stylesheet" href="http://localhost:8002/bootstrap/3.3.4/css/bootstrap.min.css">

</body>

</html>
"""

matches = []
scriptRegex = r"\<script.+\>\<\/script\>"
linkRegex = r"\<link.+\>"

try:
	compiledScriptRegex = re.compile(scriptRegex)
	compiledLinkRegex = re.compile(linkRegex, re.DOTALL)
except:
	print("Failed to compile regexes.")


try:
	# scriptMatch = compiledScriptRegex.finditer(self._helpers.bytesToString(response))
	# linkMatch = compiledLinkRegex.finditer(self._helpers.bytesToString(response))
	scriptMatch = compiledScriptRegex.findall(response)
	linkMatch = compiledLinkRegex.findall(response)
except:
	print("Failed to run regexes.")

try:
	for match in scriptMatch:
		# print("Found script match: " + str(match.group()))
		# print("Found script match: " + str(match))
		matches.append(match)
	# for match in linkMatch:
	# 	# print("Found link match: " + str(match.group()))
	# 	print("Found link match: " + str(match))
	# 	matches.append(match)
except:
	print("Failed to iterate through matches.")

domain = "localhost:8002"

try:
	for match in scriptMatch:
		try:
			if domain.lower() in match.lower():
				print("Domain match found in")
			else:  # Parse script/link for integrity attribute
				print("Different domain, looking for integrity attribute...")
				integrityRegex = r"integrity=('|\")sha(256|384|512)-[a-zA-Z0-9\/=+]+('|\")"
				compiledIntegrityRegex = re.compile(integrityRegex)
				if "integrity" in match:
					print("Integrity found in for...in.")
				try:
					result = compiledIntegrityRegex.search(match)
					print(result.group())
				except:
					print("Failed to get integrity regex match.")
		except:
			print("Failed to match against domain.")
except:
	print("Failed to print matches.")