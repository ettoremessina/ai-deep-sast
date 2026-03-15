# AI-Powered OWASP Top 10 Security Report

### sample_vuln.py (Lines 12-12)
**Semgrep finding:** Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using an object-relational mapper (ORM) such as SQLAlchemy which will protect your queries.

**AI OWASP mapping/explanation:**


---
### sample_vuln.py (Lines 28-28)
**Semgrep finding:** Detected Flask route directly returning a formatted string. This is subject to cross-site scripting if user input can reach the string. Consider using the template engine instead and rendering pages with 'render_template()'.

**AI OWASP mapping/explanation:**


---
### sample_vuln.py (Lines 28-28)
**Semgrep finding:** Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site scripting vulnerability, which could let attackers steal sensitive user data. To be sure this is safe, check that the HTML is rendered safely. Otherwise, use templates (`django.shortcuts.render`) which will safely render HTML instead.

**AI OWASP mapping/explanation:**


---
### sample_vuln.py (Lines 28-28)
**Semgrep finding:** Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site scripting vulnerability, which could let attackers steal sensitive user data. To be sure this is safe, check that the HTML is rendered safely. Otherwise, use templates (`flask.render_template`) which will safely render HTML instead.

**AI OWASP mapping/explanation:**


---
### sample_vuln.py (Lines 33-34)
**Semgrep finding:** Request data detected in os.system. This could be vulnerable to a command injection and should be avoided. If this must be done, use the 'subprocess' module instead and pass the arguments as a list. See https://owasp.org/www-community/attacks/Command_Injection for more information.

**AI OWASP mapping/explanation:**


---
### sample_vuln.py (Lines 34-34)
**Semgrep finding:** User data detected in os.system. This could be vulnerable to a command injection and should be avoided. If this must be done, use the 'subprocess' module instead and pass the arguments as a list.

**AI OWASP mapping/explanation:**


---
### sample_vuln.py (Lines 34-34)
**Semgrep finding:** Found user-controlled data used in a system call. This could allow a malicious actor to execute commands. Use the 'subprocess' module instead, which is easier to use without accidentally exposing a command injection vulnerability.

**AI OWASP mapping/explanation:**


---
### sample_vuln.py (Lines 39-40)
**Semgrep finding:** Found user data in a call to 'eval'. This is extremely dangerous because it can enable an attacker to execute arbitrary remote code on the system. Instead, refactor your code to not use 'eval' and instead use a safe library for the specific functionality you need.

**AI OWASP mapping/explanation:**


---
### sample_vuln.py (Lines 40-40)
**Semgrep finding:** Detected user data flowing into eval. This is code injection and should be avoided.

**AI OWASP mapping/explanation:**


---
