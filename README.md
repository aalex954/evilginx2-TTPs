# evilginx2-tuned

A fork of kgretzky/evilginx2 including my TTPs, IOC header removal, customizations and additional configurations to prevent detections by EOP/SafeLinks.

- IOC Removal
- EOP/MSFT IP Blacklist
- User-Agent Filtering
- SPF / DKIM
- Domain Aging
- Site Ranking
- CloudFlare CAPTCHA
- Google AMP Redirects
- Manipulate "Display Name" for Outlook


## IOC Removal

Removed both IOC headers in ```evilginx2-tuned/core/http_proxy.go```

### Hello, World!

request header containing the following:

``` js
X-Evilginx: : [80 253 149 118 169 176 183 169 182 184] 
```

---

#### Removed Code

> byte sequence
> ``` go
> e := []byte{208, 165, 205, 254, 225, 228, 239, 225, 230, 240}
> ```

> decrypt byte array using bitwise XOR operation with constant 0x88
> ``` go
> for n, b := range e {
> 	e[n] = b ^ 0x88
> }
> ```

> decrypted byte array
> ``` go
> [80 253 149 118 169 176 183 169 182 184]
>

> set request header
> ``` go
> req.Header.Set(string(e), e_host)
> ```

> if request authorized
> ``` go
> p.cantFindMe(req, e_host)
> ```

> function takes hostname
> ``` go
> cantFindMe(req *http.Request, nothing_to_see_here string)
> ```

> encrypted string as byte array
> ``` go
> var b []byte = []byte("\x1dh\x003,)\",+=")
> ```

> decrypt string using bitwise XOR operation with constant 0x45
> ``` go
> for n, c := range b {
> 	b[n] = c ^ 0x45
> }
> ```

> decrypted string
> ``` go
> "X-Evilginx"
> ```

> set the request header with decrypted string
> ``` go
> req.Header.Set(string(b), nothing_to_see_here)
> ```

> header
> ``` js
> X-Evilginx: : [80 253 149 118 169 176 183 169 182 184]
> ```

---

### egg2

request header containing the following:

``` js
X-Evilginx : {req.Host}
```

#### Removed Code

> store request url
> ``` go
> egg2 := req.Host
> ```

> byte array of hex values
> ``` go
> []byte{0x94, 0xE1, 0x89, 0xBA, 0xA5, 0xA0, 0xAB, 0xA5, 0xA2, 0xB4}
> ```

> bitwise XOR
> ``` go
> for n, b := range hg {
>    hg[n] = b ^ 0xCC
> }
> ```
   
> set request header
> ``` go
> req.Header.Set(string(hg), egg2)
> ```

> base-64 decoded
> ``` js
> X-Evilginx : {req.Host} 
> ```

---

## IP Blacklist

A custom blacklist file has been included in this repo. It is located at 
```Custom/blacklist.txt```

In an attempt to prevent EOP from scanning the phishing links a blacklist was generated and includes all IP addresses associated to MSFT owned ASNs.

This file needs to be copied into the ```~/.evilginx/``` directory.

Microsoft reports IP ranges and their associated roles, it can be referenced here:

- https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide
- https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7


Although somewhat redundant (in the context of EOP) an updated list can be generated.

> I have discovered EOP __does__ connect from IPs that are not listed in the above links.

---

### Generate New Blacklist

An updated blaklist can be generated using one of the methods below.

#### ASN2IP

A PowerShell Core [tool](https://github.com/aalex954/ASN-2-IP) to track Microsoft IPs for use in security research, firewall configuration, routing, and troubleshooting.


#### MSFT-IP-Tracker

This [list](https://github.com/aalex954/MSFT-IP-Tracker) is generated and published each day representing all IP address ranges owned by Microsoft as reported by WHOIS/ASN ownership.


##### An updated list can be downloaded here

[msft_asn_ip_ranges.txt](https://github.com/aalex954/MSFT-IP-Tracker/releases/latest/download/msft_asn_ip_ranges.txt)

```bash
wget https://github.com/aalex954/MSFT-IP-Tracker/releases/latest/download/msft_asn_ip_ranges.txt
```

---

## User-agent Filtering

User-agent filtering allows you to filter requests to your phishing link based on the originating _User-Agent_ header and may be useful to prevent link scanning.

> Set an _ua_filter_ option for any of your lures, as a whitelist regular expression, and only requests with matching User-Agent header will be authorized.

Syntax:

```bash
lures edit <id> ua_filter "REGEX_PATTERN"
``` 

Here is an example of a regex pattern that allows only the following user-agents:

```bash
.*(Windows NT 10.0|CrOS|Macintosh|Windows NT 6.1|Ubuntu|).*\im
```


This regex pattern will allow any user-agents that are not included in the pattern:

```bash
^(?!.*(?:Googlebot|YandexAccessibilityBot|bingbot)).*$\im
```

## Hide

Hiding a phishlet essentially redirects requests to a hidden phishlet to a URL that is defined in the config section.
During the initial stages of the campaign you may want to hide your phishlet so that EOP does not have a chance to scan the URL.
Before sending out the phishing email, hide the phishlet by issuing this command:

> outlook is used here as an example

```phishlets hide outlook```

After about 10 minutes you can unhide the phsihlet. 

```phishlets unhide outlook```

A downside to this method is that if a user clicks on the phishing email in the first 10 minutes, they will be reditected and will not get phished.

---

## DNS

To increase our chance of bypassing EOP, SafeLinks, spam filtering, etc. we need to try to increase our domains reputation. 
The domains age, clasification, and usage of proper email verification techniques all impact the reputation.

### Domain Names

To perform any phishing attack you must control some domain. Its a good idea to buy a handful every few months so you always have aged domains on hand. Try choosing domain names that makes sense in the context of your campaign. Generic sounding domains containing keywords such as 'corporate' or 'internal' are safe bets. Also consider the phishing lure being used. 

---

### SPF / DKIM Records

#### SPF - Sender Policy Framework

A TXT record needs to be created containing the following

| Key | Value |
|--------------------|---------------------------------|
| _dmarc.DOMAIN.COM | v=DMARC1; p=quarantine; pct=100;|

### DKIM - DomainKeys Identified Mail

While DKIM isn’t required, having emails that are signed with DKIM appear more legitimate to your recipients and are less likely to end up in the junk or spam folders.
The steps to generate a domain key will be different depending on your email provider. Ultimately, this information will be put into a TXT record similar to what we did for SPF.

| Key | Value |
|--------------------|---------------------------------|
| selector1._domainkey | selector1-contoso-com._domainkey.contoso.onmicrosoft.com|

---

#### Domain Aging

It is best practice to use aged domains due as newer domains are susceptible to being flagged for being recently created. Organizations can actually configure their email filtering to recognize newly registered domains to ensure they are blocked from entering their employees' mailboxes. Domains should be aged as long as possible before being used in a campaign. 

---

## Site Classification

Site categorization is used to determine specific categories for a website. If this step is skipped, a domain is at risk for being seen as uncategorized, which may look suspicious and end up getting flagged as malicious.

Ensure your site is categorized by one or more of the following:

- Fortiguard
- Symantec + BlueCoat
- Checkpoint
- Palo Alto
- Sophos (submission only)
- TrendMicro
- Brightcloud
 
It is best to usually categorize your site as Business, Finance, or IT. It is important to use a real email address and have real content pointing to your 'www' A record to ensure the site looks like a reputable domain. Site categorization takes up to 1-2 days. You can check on the status of your site by revisiting a few of the links mentioned above.

---

## CloudFlare CAPTCHA

\\TODO

---

## Google AMP Redirects

https://cofense.com/blog/google-amp-the-newest-of-evasive-phishing-tactic/

Google Accelerated Mobile Pages (AMP) can be abused to bypass phishing protections by presenting a trustworthy domain with containing a redirect.

The lure URL can be embedded into the Google AMP URL like this:

```https://www.google.com/amp/s/``` / ```phish_url``` or ```https://www.google.co.uk/amp/s/``` / ```phish_url```


---

## Manipulate "Display Name" for Outlook

The "display name" field in the email can be used to manipulate to "from email" field off the screen.

This is working in Outlook desktop and OWA as of 08/08/23

Because the "display name" and "from email" are in the same visual element, the "from email" can be manipulated by pushing it out of the displayed element using non-visable Unicode characters.

For example:

```
Your Manager\s\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\u2800\sTo:colleague1<colleague1@company\.com>
```

or

```
Your Manager <your.manager@company.com>⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
```

Would display similar to this:

![Screenshot 2023-08-08 234239](https://github.com/aalex954/evilginx2-tuned/assets/6628565/a88127e3-04fa-4a0a-8257-938e7736fbd7)

Some possible characters:

- Space (U+0020)
- No-Break Space (U+00A0)
- Ogham Space Mark (U+1680)
- Mongolian Vowel Separator (U+180E)
- En Quad (U+2000)
- Em Quad (U+2001)
- En Space (U+2002)
- Em Space (U+2003)
- Three-Per-Em Space (U+2004)
- Four-Per-Em Space (U+2005)
- Six-Per-Em Space (U+2006)
- Figure Space (U+2007)
- Punctuation Space (U+2008)
- Thin Space (U+2009)
- Hair Space (U+200A)
- Zero Width Space (U+200B)
- Zero Width Non-Joiner (U+200C)
- Zero Width Joiner (U+200D)
- Line Separator (U+2028)
- Paragraph Separator (U+2029)
- Narrow No-Break Space (U+202F)
- Medium Mathematical Space (U+205F)
- Ideographic Space (U+3000)
- Braille Pattern Blank (U+2800)

Regex pattern: ```[\u0020\u00A0\u1680\u180E\u2000-\u200A\u200B-\u200D\u2028-\u2029\u202F\u205F\u3000\u2800]```


All credit goes to: https://gitlab.com/email_bug/outlook_email_auth_bypass


### Detection

To counter this, a regex pattern can be used:

```(\w+\s)+[\u0020\u00A0\u1680\u180E\u2000-\u200A\u200B-\u200D\u2028-\u2029\u202F\u205F\u3000\u2800]+\sTo:\w+<\w+@\w+\.\w+>```

This regex should match a string with any number of words followed by a sequence of blank-appearing characters, then the "To:" string, and an email.

or more generically

```(\w+\s)+[\u0020\u00A0\u1680\u180E\u2000-\u200A\u200B-\u200D\u2028-\u2029\u202F\u205F\u3000\u2800]+.*```

This pattern now matches any number of words followed by a sequence of blank-appearing characters and then any sequence of characters afterward.

![Screenshot 2023-08-08 235841](https://github.com/aalex954/evilginx2-tuned/assets/6628565/68be4518-b1d5-476c-9c0b-ce7a0aa1a255)

---
