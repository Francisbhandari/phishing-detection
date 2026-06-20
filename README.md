# URL phishing-detector

## About
This project detects phishing URLs.

We have assigned score points 1-3 in each checks, 1 being the lowest and 3 being the highest.
Following are the max scores of each check:
url_length = 2
num_hyphen = 2
num_dots = 2
num_digits = 2
has_ip = 3
has_@ = 3
num_subdomain = 2
num_sus_word = 2
sus_tld = 2
path_length = 2
has_hex_encoding = 3
uses_https = 3 (if not condition)

Total max score = 28

SAFE (0% - 25%) -> Normal URL
SUSPICIOUS (25% - 50%) -> Some risk signals
PHISHING (50% +) -> Many red flags

Applying above into max score:
SAFE -> 25% of 28 ~~ 7
SUSPICIOUS -> 50% of 28 ~~ 14
PHISHING -> >14

So,
SAFE <=7
SUSPICIOUS <=14
PHISHING >14

