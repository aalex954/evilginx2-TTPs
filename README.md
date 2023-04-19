# evilginx2-removed-iocs

A forked repo containing modifications and additional configurations to prevent detections by EOP/SafeLinks.

- IOC Removal
- EOP/MSFT IP Blacklist
- User-Agent Filtering


## IOC Removal

Removed the IOC embeded in the response header. 

- store request url
```
egg2 := req.Host
```

- byte array of hex values
```
[]byte{0x94, 0xE1, 0x89, 0xBA, 0xA5, 0xA0, 0xAB, 0xA5, 0xA2, 0xB4}
```

- bitwise XOR
     ```
      for n, b := range hg {
        hg[n] = b ^ 0xCC
       }
    ```
   
- set request header

```
req.Header.Set(string(hg), egg2)
```
- base-64 decoded
  - X-Evilginx : {req.Host}

## IP Blacklist

A custom blacklist file has been included in this repo. It is located at 
```Custom/blacklist.txt```

In an attempt to prevent EOP from scanning the phishing links a blacklist was generated and includes all IP addresses associated to MSFT owned ASNs.

This file needs to be copied into the ```~/.evilginx/``` directory.

Microsoft reports IP ranges and their associated roles, it can be referenced here:

- https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide
- https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7

An additional and likely somewhat redundant (in the context of EOP) list can be generated using the following tool: ASN-2-IP

- https://github.com/aalex954/ASN-2-IP

This list represents all IP address ranges owned by Microsoft as reported by WHOIS/ASN ownership.

__An updated list can be downloaded here:__

https://github.com/aalex954/MSFT-IP-Tracker/releases/download/{%Y%m%d}/msft_asn_ip_ranges.txt

_Update the URL in the following format: %Y%m%d or YYYYMMDD_

## User-agent Filtering

User-agent filtering is a new feature in version 2.4. It allows you to filter requests to your phishing link based on the originating _User-Agent_ header.

This may be useful to prevent link scanning and I intend to update with a regex pattern in the future.

- Set an _ua_filter_ option for any of your lures, as a whitelist regular expression, and only requests with matching User-Agent header will be authorized.

As an example, if you'd like only requests from iPhone or Android to go through, you'd set a filter like so:

```lures edit <id> ua_filter "REGEX_PATTERN"``` 

Here is an example of a regex pattern that allows only the following user-agents:

```.*(Windows NT 10.0|CrOS|Macintosh|Windows NT 6.1|Ubuntu|).*\im```


This regex pattern will allow any user-agents that are not included in the pattern:

```"^(?!.*(?:Googlebot|YandexAccessibilityBot|bingbot)).*$\im```

## Hide

Hiding a phishlet essentially redirects requests to a hidden phishlet to a URL that is defined in the config section.
During the initial stages of the campaign you may want to hide your phishlet so that EOP does not have a chance to scan the URL.
Before sending out the phishing email, hide the phishlet by issuing this command:

note: outlook is used here as an example

```phishlets hide outlook```

After about 10 minutes you can unhide the phsihlet. 

```phishlets unhide outlook```

A downside to this method is that if a user clicks on the phishing email in the first 10 minutes, they will be reditected and will not get phished.
