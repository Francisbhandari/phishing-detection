import lexical as l
import content as c
import network as n
from model import predict as p

url = input("Enter url to check: ")

lex_ftrs   = l.analyze_url(url)
whois_ftrs = n.whois_features(lex_ftrs['domain'])
dns_ftrs   = n.dns_features(lex_ftrs['domain'])       
web_ftrs   = c.fetch_page(url)

all_ftrs = lex_ftrs | whois_ftrs | dns_ftrs | web_ftrs

l_score = l.lex_score(all_ftrs)
n_score = n.net_score(whois_ftrs, dns_ftrs)          
c_score = c.content_score(c.content_features(web_ftrs))

all_ftrs['lex_score']     = l_score 
all_ftrs['net_score']     = n_score
all_ftrs['content_score'] = c_score

ml_score  = float(p.predict(all_ftrs)[0])

combined = (
    0.20 * l_score +
    0.20 * n_score +
    0.20 * c_score +
    0.40 * ml_score
)

print(f"\nURL          : {url}")
print(f"Lexical score: {l_score:.3f}")
print(f"Network score: {n_score:.3f}")
print(f"Content score: {c_score:.3f}")
print(f"ML score     : {ml_score:.3f}")
print(f"Combined     : {combined:.3f}")
print(f"Verdict      : {'PHISHING' if combined >= 0.5 else 'LIKELY SAFE'}")
