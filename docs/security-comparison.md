# Vulnerable vs Secure Code Comparison

## 🔍 Overview

This document compares the vulnerable and secure implementations of XML parsing, highlighting the exact differences that prevent XXE attacks.

---

## 🚨 Vulnerable Configuration (DANGEROUS)

**File:** `vulnerable_app/app.py`
```python
def parse_xml_vulnerable(xml_content):
    """
    VULNERABLE XML parser - External entities are ENABLED
    This is intentionally insecure for demonstration purposes!
    """
    parser = etree.XMLParser(
        resolve_entities=True,   # ❌ VULNERABLE: Enables external entities
        no_network=False,        # ❌ VULNERABLE: Allows network access
        dtd_validation=False,
        load_dtd=True,          # ❌ VULNERABLE: Loads DTD
        remove_blank_text=False,
        huge_tree=True          # ❌ VULNERABLE: No size limits
    )
    
    root = etree.fromstring(xml_content.encode('utf-8'), parser)
    return extract_data(root)
```

**Problems:**
- ✗ `resolve_entities=True` - **Processes external entities** (XXE vulnerability!)
- ✗ `no_network=False` - **Allows network connections** (SSRF possible)
- ✗ `load_dtd=True` - **Loads Document Type Definitions** (entity expansion)
- ✗ `huge_tree=True` - **No protection against DoS** (Billion Laughs possible)

---

## ✅ Secure Configuration (SAFE)

**File:** `secure_app/app.py`
```python
def parse_xml_secure(xml_content):
    """
    SECURE XML parser - External entities are DISABLED
    This configuration prevents XXE attacks!
    """
    parser = etree.XMLParser(
        resolve_entities=False,  # ✅ SECURE: Disables external entities
        no_network=True,         # ✅ SECURE: Blocks network access
        dtd_validation=False,
        load_dtd=False,         # ✅ SECURE: Does not load DTD
        remove_blank_text=False,
        huge_tree=False         # ✅ SECURE: Limits tree size (DoS protection)
    )
    
    root = etree.fromstring(xml_content.encode('utf-8'), parser)
    return extract_data(root)
```

**Security Features:**
- ✓ `resolve_entities=False` - **Blocks external entities** (XXE prevented!)
- ✓ `no_network=True` - **No network access** (SSRF prevented)
- ✓ `load_dtd=False` - **DTD not loaded** (no entity expansion)
- ✓ `huge_tree=False` - **Size limits enforced** (DoS attacks mitigated)

---

## 📊 Side-by-Side Comparison

| Configuration | Vulnerable App | Secure App | Impact |
|--------------|----------------|------------|---------|
| **resolve_entities** | `True` ❌ | `False` ✅ | XXE Prevention |
| **no_network** | `False` ❌ | `True` ✅ | SSRF Prevention |
| **load_dtd** | `True` ❌ | `False` ✅ | Entity Expansion Prevention |
| **huge_tree** | `True` ❌ | `False` ✅ | DoS Prevention |
| **Port** | 5000 | 5001 | - |
| **UI Color** | Red (Warning) | Green (Safe) | Visual indicator |

---

## 🔥 Attack Results Comparison

### File Disclosure Attack

**XXE Payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

**Vulnerable App Result:**
```
✅ Attack SUCCESSFUL
Displays: Full contents of /etc/passwd (9344 bytes)
```

**Secure App Result:**
```
✅ Attack BLOCKED
Displays: <data/> (empty - entity not resolved)
```

---

### SSRF Attack

**XXE Payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:5000/health">
]>
<data>&xxe;</data>
```

**Vulnerable App Result:**
```
⚠️ Partially blocked by lxml security features
Modern lxml blocks HTTP in external entities
```

**Secure App Result:**
```
✅ Attack BLOCKED
Entity not resolved at all
```

---

### DoS (Billion Laughs) Attack

**XXE Payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>
```

**Vulnerable App Result:**
```
✅ Attack BLOCKED (lxml has built-in limits)
Error: Maximum entity amplification factor exceeded
```

**Secure App Result:**
```
✅ Attack BLOCKED
Entities not expanded at all
```

---

## 🛡️ Defense in Depth

### Multiple Layers of Protection

**Secure App implements:**

1. **Parser Configuration** (Primary defense)
   - Disabled external entities
   - Blocked network access
   - DTD loading disabled

2. **Input Validation** (Secondary defense)
   - File size limits (16MB)
   - File type validation (.xml only)
   - Content-Type validation

3. **Error Handling** (Tertiary defense)
   - Graceful error messages
   - No sensitive information leakage
   - Proper exception handling

---

## 📚 Best Practices Implemented

### ✅ DO (Secure App)

- ✓ Disable external entity resolution
- ✓ Block network access in XML parser
- ✓ Don't load DTDs
- ✓ Limit XML document size
- ✓ Use secure parser configuration by default
- ✓ Validate input before parsing
- ✓ Implement proper error handling

### ❌ DON'T (Vulnerable App)

- ✗ Enable external entities
- ✗ Allow network access
- ✗ Load DTDs
- ✗ Allow unlimited document size
- ✗ Trust user input
- ✗ Use default parser settings without review

---

## 🔧 How to Fix XXE in Your Applications

### Python (lxml)

**Before (Vulnerable):**
```python
parser = etree.XMLParser()
root = etree.fromstring(xml_data, parser)
```

**After (Secure):**
```python
parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    load_dtd=False
)
root = etree.fromstring(xml_data, parser)
```

### Java

**Before (Vulnerable):**
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(new InputSource(new StringReader(xml)));
```

**After (Secure):**
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(new InputSource(new StringReader(xml)));
```

### PHP

**Before (Vulnerable):**
```php
$dom = new DOMDocument();
$dom->loadXML($xml);
```

**After (Secure):**
```php
libxml_disable_entity_loader(true);
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);
```

---

## 🎓 Key Takeaways

1. **One setting makes the difference**: `resolve_entities=False` is the critical security control
2. **Defense in depth**: Multiple security layers provide better protection
3. **Default configurations**: Always review and harden default XML parser settings
4. **Testing is essential**: Both vulnerable and secure versions should be tested
5. **Modern parsers help**: Even lxml has some built-in protections (DoS limits)

---

## 📖 References

- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [lxml Security Documentation](https://lxml.de/FAQ.html#how-do-i-use-lxml-safely-as-a-web-service-endpoint)
- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)