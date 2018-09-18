# coding=utf8
# the above tag defines encoding for this document and is for Python 2.x compatibility

import re

# regex for getting URL base domain, won't work for script/stylesheet paths
regex = r"([a-zA-Z0-9-]+)(\.[a-zA-Z]{2,5})?(\.[a-zA-Z]+$)"
regex2 = r"\<script.+\>\<\/script\>"

test_str = ("domain.com/test\n"
	"subdomain.domain.com\n"
	"sub.sub.subdomain.domain.com\n"
	"sub.subdomain.com.au\n"
	"coool.new.domain.luxury\na.b.c.d.g.com\n"
    "https://example.com/example-frameworkjs\n"
	"https://example.com/test")

test_str2 = '<script src="https://example.com/example-framework.js" integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" crossorigin="anonymous"></script>'

matches = re.finditer(regex, test_str, re.MULTILINE)
matches2 = re.finditer(regex2,test_str2)

for match in matches:
    print(match.group())
for match in matches2:
    print(match.group())




















# for matchNum, match in enumerate(matches):
#     matchNum = matchNum + 1

#     print ("Match {matchNum} was found at {start}-{end}: {match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))

#     for groupNum in range(0, len(match.groups())):
#         groupNum = groupNum + 1

#         print ("Group {groupNum} found at {start}-{end}: {group}".format(groupNum = groupNum, start = match.start(groupNum), end = match.end(groupNum), group = match.group(groupNum)))

# # Note: for Python 2.7 compatibility, use ur"" to prefix the regex and u"" to prefix the test string and substitution.
