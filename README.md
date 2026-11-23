
Functional Requirements (FR)


ID	Requirement	Acceptance Criteria	Priority
FR-01	Anonymised Qualys CSV Ingestion	The system parses a CSV dataset of vulnerability scan findings (QID, CVE, Title, Severity, CVSS, Status, Host, IP, OS, Solution) and renders records without errors.	Must Have
FR-02	Executive KPI Summary Cards	The main dashboard displays live aggregated counts for Total Findings, Critical (Severity 5), High (Severity 4), and Active/Unpatched vulnerabilities.	Must Have
FR-03	Keyword Search	Users can search vulnerabilities by keyword across CVE ID, QID, Title, and Host fields with case-insensitive matching.	Must Have
FR-04	Multi-Criteria Filtering	Users can filter the vulnerability table simultaneously by Severity (1–5), Status (New, Active, Re-Opened, Fixed), and OS.	Must Have
FR-05	Vulnerability Remediation Detail View	Clicking any finding opens a dedicated detail page/modal showing full CVSS score, affected host details, threat description, and recommended remediation steps.	Should Have
FR-06	Filtered CSV Export	Users can export their currently filtered subset of vulnerabilities back to a clean CSV file for ticket assignment.	Could Have


Non-Functional Requirements (NFR)


ID	Requirement	Target / Metric
NFR-01	Performance & Responsiveness	Search and filter queries execute and update the UI in under 500 ms for datasets up to 2,000 rows.
NFR-02	Usability & Accessibility	Responsive layout usable on desktop and laptop screens (1280px+), using colour-coded severity badges alongside text labels for colour-blind accessibility.
NFR-03	Maintainability & Modularity	Codebase separates presentation (frontend/), API logic (backend/), business/data logic (services/), and automated tests (tests/).
NFR-04	Availability & Hosting	Application is deployed publicly on a zero-cost platform (Render) with automated builds triggered from the main branch.


Security Requirements (SEC)


ID	Requirement	Implementation Control
SEC-01	Data Anonymisation & Privacy	All real internal IP addresses, DNS hostnames, and organizational identifiers are scrubbed/replaced with RFC 5737 documentation IPs and synthetic hostnames prior to ingestion.
SEC-02	Session-Based Authentication	Protected dashboard routes require valid user login via Flask session management (services/auth.py) with hashed passwords (werkzeug.security).
SEC-03	XSS & CSV Formula Injection Prevention	All dynamic CSV fields are auto-escaped via Jinja2 templates, and exported CSV cells starting with =, +, -, or @ are sanitised.
SEC-04	Secrets Management	Flask SECRET_KEY and demo credentials are loaded via environment variables (.env excluded via .gitignore) rather than hardcoded in source control.

![Initial Kanban Board](docs/images/kanban_initial.jpeg)
