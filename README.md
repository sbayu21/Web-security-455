# CPSC 455 - Web Security

## Project 3 - Fall 2024



## Clone the repository and run the code

Cloning the repo and starting the application went smoothly.

Screenshot of the running application

Open the browser to the app’s location showed the various pages.

Screenshot of the home page Screenshot of results from pinging reddit
![image](https://github.com/user-attachments/assets/6e9a6c61-2de7-48b3-9af1-830b093ad4f0)

## Find and exploit the vulnerabilities

### SQL Injection Vulnerabilities

##### SQL Injection Instance #

Vulnerability Name: URL query parameter and “Add a comment form” on Comments Page -
"http://ping.127.0.0.1.nip.io:8080/?page=comments&hostname=localhost" is vulnerable to SQL
Injection

Vulnerable URL/Area: https://example.com/home - Comments Page

Vulnerable Form Values: Comment, Your name

Vulnerable Query Params: hostname

Vulnerability Description: The query param hostname and the form values (Comment and
Your Name) are sent to the endpoint POST /comments. This endpoint executes an SQL insert
statement using the values mentioned without sanitizing or validating the user-provided inputs.

Severity: Critical

Risk Rating: High

CVE: N/A

CWE-ID: CWE-89: Improper Neutralization of Special Elements used in an SQL Command
('SQL Injection')

CVSS Score: 9.8 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

Vulnerability Class: SQL Injection


Impact of Vulnerability: The vulnerability of SQL injection on the Comments Page has an
enormous impact on the system. This vulnerability allows an attacker to any database query
they wish. By exploiting this vulnerability, an attacker can potentially access sensitive data in the
database, or delete any tables they wish.

Steps to reproduce:

1. Go to the Comments Page
(http://ping.127.0.0.1.nip.io:8080/?page=comments&hostname=localhost).
2. Enter some text in the comment section.
3. Enter some malicious SQL script in the Your Name section

```
3a. attacker’); DROP TABLE comments; –
```
4. Submit payload
5. Verify any page dependent on comments is broken

Proof of Concept (PoC)

try {

await dbExec(`

INSERT INTO comments(hostname, comment, commenter)

VALUES ('${hostname}', '${comment}', '${commenter}')`)

} catch (err) {

console.error(err)

}




Mitigation/Remediation

1. Use parameterized values in the SQL command for committing a comment rather than
    pulling in directly from the request payload for the hostname, comment, and commenter
    values

```
app.post('/comments', async (req, res) => {
const { hostname, comment, commenter } = req.body
```
```
try {
await dbExec(
`INSERT INTO comments(hostname, comment,
commenter) VALUES (?, ?, ?)`,
[hostname, comment, commenter]
)
} catch (err) {
console.error(err)
}
```
```
res.redirect(`/?page=comments&hostname=${hostname}`)
})
```
Screenshot of implementing the attack Screenshot of the malicious SQL being inserted safely

References

- https://cwe.mitre.org/data/definitions/89.html
- https://nvd.nist.gov/vuln-metrics/cvss/v3-
    calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H&version=3.


##### SQL Injection Instance #

Vulnerability Name: URL query parameter on “History” Page -
"http://ping.127.0.0.1.nip.io:8080/?page=history&hostname=localhost" is vulnerable to SQL
Injection

Vulnerable URL/Area: [http://ping.127.0.0.1.nip.io:8080/?page=history&hostname=localhost](http://ping.127.0.0.1.nip.io:8080/?page=history&hostname=localhost) -
History Page

Vulnerable Query Params: hostname

Vulnerability Description: The query parameter hostname is passed directly into an SQL
query without sanitization or validation on the History Page. This occurs when fetching host
history records from the database. By injecting malicious SQL into the hostname parameter, an
attacker can manipulate the underlying database query, potentially retrieving unauthorized data
or altering the database’s structure.

Severity: Critical

Risk Rating: High

CVE: N/A

CWE-ID: CWE-89: Improper Neutralization of Special Elements used in an SQL Command
('SQL Injection')

CVSS Score: 8.1 AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H

Vulnerability Class: SQL Injection

Impact of Vulnerability: This endpoint is theoretically vulnerable to SQL injection however it
would be extremely difficult to exploit. The reason for the difficulty is due to a command that is
run before the query. That command uses the same hostname query param. Any malformed
SQL passed into that hostname will likely cause the command to fail before the SQL can be run.
Due to this, it is very unlikely that this vulnerability will be exploited. However, this code should
be mitigated since it’s possible the command code changes allowing the SQL injection
vulnerability to be more exposed.


Steps to reproduce:

1. Navigate to the History Page (e.g.,
[http://ping.127.0.0.1.nip.io:8080/?page=history&hostname=localhost).](http://ping.127.0.0.1.nip.io:8080/?page=history&hostname=localhost).)
2. Modify the hostname query parameter to include malicious SQL code. For example:
[http://ping.127.0.0.1.nip.io:8080/?page=history&hostname=';DROP](http://ping.127.0.0.1.nip.io:8080/?page=history&hostname=';DROP) TABLE results;--
3. Load the modified URL in a web browser.
4. Observe the behavior of the application. If the query is executed, you may see errors or find
that expected host history data is missing. Subsequent attempts to view host history or related
data may fail due to the dropped or altered table.

Proof of Concept (PoC)

N/A - It is not possible to exploit this vulnerability. Any attempt results in a system failure
unrelated to the SQL injection vulnerability.

Passing malicious SQL in the hostname query param Screenshot of the application showing failure


Mitigations/Remediation

1. Use parameterized values in the SQL command to fetch past results rather than pulling
    in directly from the request payload for the hostname value

```
_.history = await dbAll(
`
SELECT
*
FROM
results
WHERE
hostname =?
ORDER BY
timestamp DESC
LIMIT 100
`,
[ _.hostname ]
)
```
References

- https://cwe.mitre.org/data/definitions/89.html
- https://nvd.nist.gov/vuln-metrics/cvss/v3-
    calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H&version=3.


##### SQL Injection Instance #

Vulnerability Name: URL query parameter on “Comments” Page -
"http://ping.127.0.0.1.nip.io:8080/?page=comments" is vulnerable to SQL Injection

Vulnerable URL/Area: [http://ping.127.0.0.1.nip.io:8080/?page=comments&hostname=localhost](http://ping.127.0.0.1.nip.io:8080/?page=comments&hostname=localhost)

Vulnerable Query Params: hostname

Vulnerability Description: The hostname query parameter is used in an SQL query to fetch
comments from the database for a given hostname. The SQL query is executed in a function
that is limited to one SQL query. Given this, the impact is lower since the malicious query has to
be formatted within the original query. This lowers the impact significantly.

Severity: High

Risk Rating: High

CVE: N/A

CWE-ID: CWE-89: Improper Neutralization of Special Elements used in an SQL Command
('SQL Injection')

CVSS Score: 7.3 AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L

Vulnerability Class: SQL Injection

Impact of Vulnerability: When exploited an attacker can view all the comments in the
database on one page. As the application stands this does not seem too problematic. But in a
production setting, this may cause performance issues. Also if the application was to be
modified to include some level of authorization on different hostnames or comments the attacker
could get around this. Even though the impact appears to be restricted to one table, expert
attackers may be able to exploit this vulnerability more damagingly than we anticipate.

Steps to reproduce:

1. Navigate to the Comments Page
(http://ping.127.0.0.1.nip.io:8080/?page=comments&hostname=localhost).
2. Update the hostname query parameter to include a malicious SQL payload, such as:
[http://ping.127.0.0.1.nip.io:8080/?page=comments&hostname=%27%20OR%20%271%27=%](http://ping.127.0.0.1.nip.io:8080/?page=comments&hostname=%27%20OR%20%271%27=%)
71
3. Verify that all comments are showing


Proof Of Concept:
Mitigations/Remediation

1. Use parameterized values in the SQL commands rather than pulling in directly from the
    request payload for the hostname, comment and commenter values

```
_.comments = await dbAll(`
SELECT
*
FROM
comments
WHERE
hostname =?
ORDER BY
timestamp DESC
LIMIT 100
`, [_.hostname])
```
##### SQL Injection Instance #

Vulnerability Name: Hostname Parameter on “Ping” Endpoint - "POST /ping" is vulnerable to
SQL Injection

Vulnerable URL/Area: POST /ping

Vulnerable Form Values: hostname

Vulnerability Description: When inserting ping results into the results database table, the
application takes the hostname value provided by the user and directly interpolates it into the
SQL INSERT statements without any sanitization or parameterization. This allows an attacker to
submit a crafted hostname value containing malicious SQL, potentially altering database
queries. By exploiting this flaw, an attacker could insert arbitrary data, read sensitive database
content, or even drop tables—compromising the integrity and availability of the database.

Severity: High

Risk Rating: High

CVE: N/A

CWE-ID: CWE-89: Improper Neutralization of Special Elements used in an SQL Command
('SQL Injection')

CVSS Score: 5.6 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L)

Vulnerability Class: SQL Injection

Impact of Vulnerability: Similarly to SQL Injection #2 this endpoint is theoretically exploitable
but it is improbable the vulnerability is actually exploited. This is also due to a command that is
run before the SQL query. See the POC section for a screenshot that shows the error that will
occur when trying to exploit this endpoint.

Steps to Reproduce:

1. Send a POST request to the /ping endpoint with a malicious hostname value. For example:

POST /ping

Content-Type: application/x-www-form-URL-encoded

hostname=localhost';DROP TABLE results;--

2. After the request is processed, the application attempts to insert ping results using the
provided hostname.
3. Check server logs or database state. If successful, you may find that the results table has
been dropped or altered, demonstrating the SQL injection attack.


Proof of Concept (PoC):

Mitigations/Remediation

1. Use parameterized values in the SQL commands rather than pulling in directly from the
    request payload for the hostname value

```
...
app.post('/ping', async (req, res) => {
const hostname = req.body.hostname
const cmd = `ping -c 4 ${hostname} 2>&1`
```
```
try {
const { stdout } = await childProcessExec(cmd)
req.session.output = stdout
```
```
...
```
```
const statements = rtts.map(rtt => ({
query: `INSERT INTO results(hostname, round_trip_time) VALUES (?,
?)`,
params: [hostname, rtt]
}));
```
```
for (const { query, params } of statements) {
await dbExec(query, params);
} ...
```

### Remote Code Execution Vulnerabilities

##### Remote Code Execution Instance

Vulnerability Name: Dynamic Evaluation on Home Page - “http://ping.127.0.0.1.nip.io:8080/” is
vulnerable to Remote Code Execution

Vulnerable URL/Area: [http://ping.127.0.0.1.nip.io:8080](http://ping.127.0.0.1.nip.io:8080) - Home Page

Vulnerable Form Values: N/A

Vulnerable Query Params: hostname

Vulnerability Description: In the source code, the eval() function is used to dynamically
generate HTML from page templates using untrusted user input (query parameter hostname).
This could potentially provide an attack vector for RCE if expressions are able to be passed
from the client to the server, triggering the eval() function.

Severity: Moderate

Risk Rating: Moderate

CVE: N/A

CWE-ID: CWE-94: Improper Control of Generation of Code (‘Code Injection’)

CVSS Score: N/A

Vulnerability Class: Remote Code Execution (RCE)

Impact of Vulnerability:

Fortunately, no exploits have been found to take advantage of this weakness. This is because
express’s req. query middleware casts untrusted user queries into string literals, and therefore
expressions cannot be evaluated before the eval() call.

However, there is still a possibility that an attacker could take advantage of this weakness by
exploiting req .query’s default behavior by escaping the string literal and allow the untrusted
user input to be evaluated to an expression shown below:

Suppose an attacker somehow manages to escape the string literal that req.query imposes. In
that case, _.hostname will evaluate to a “8081” (port number: 8081), exfiltrating server config
secrets to the attacker by remote code execution. This potential attack could also chain into an
SQL injection attack where untrusted user input is allowed to malformed the SQL query
template set in place and HTTP response splitting attacks (by manipulating the express’s res
object notation).


Mitigation/Remediation

1. Sanitize untrusted user input (req.query.hostname).
2. Do not use eval() for dynamic HTML generation. Use a templating library like EJS or
    Handlebars instead.


### Command Injection Vulnerabilities

##### Command Injection Instance #

Vulnerability Name: Ping Requests - “http://ping.127.0.0.1.nip.io:8080/ping” is vulnerable to
command injection

Vulnerable URL/Area: POST /ping

Vulnerable Form Values: hostname

Vulnerability Description: The hostname form field being sent to the /ping endpoint in the
request body is vulnerable to Command Injection. By sending a POST request to the server with
a specially crafted payload in the request body (e.g., hostname: ...), an attacker can exploit this
vulnerability to execute malicious code on the hosting server.

Severity: High

Risk Rating: High

CVE: N/A

CWE-ID: CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS
Command Injection')

CVSS Score: 9.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H)

Vulnerability Class: Command Injection

Impact of Vulnerability: This endpoint allows for command injection that can cause a multitude
of issues. Such issues could be wiping an entire server, gaining remote access or even
dumping valuable/sensitive data from the server.

Steps to Reproduce:

1. Go to the Home page (http://127.0.0.1.nip.io:8080/?page=home)
2. Enter a malicious hostname value (e.g., cd /; rm -rf .)
3. Submit the form


Proof of Concept (PoC):

Mitigations/Remediation

1. Spawn a child process to be called with a specified command
2. Specify the “ping” command in the spawned child process
3. Handle the output data
4. Sanitize untrusted user input for hostname

Notes:

Although it is not outlined here, the Command Injection vulnerability could be used in a chain
attack alongside RCE to run something like, wget <malicious_code_file>. This would then set up
an RCE attack for running the malicious code file and potentially injecting a RAT or dumping
sensitive data.

Additionally, this Command Injection vulnerability could also be chained with Domain Specific
Language Injection exploit, where the yaml.parse() call could be invoked on a YAML file
generated by the attacker using command injection.


### Missing Exploitable Vulnerabilities

##### CRLF Injection Vulnerabilities

There are no concerns for CRLF injection in this application.

There are two vulnerabilities associated with CRLF:

Log Injection

Hackers usually exploit CRLF vulnerabilities by injecting extra lines in the server logs to disguise
their footprints while attacking the server. This makes it hard for security personnel, or software
engineers monitoring the server logs, to identify if there was a breach.

However, since this application does not maintain a log file, a log injection would not be
possible. The attacker may still use a command injection exploit to inject a log entry to the
server’s temporary log (while the server is running), but that attack would be considered a
command injection instead of a CRLF injection.

HTTP response splitting

In HTTP response splitting attacks, the attacker takes advantage of an application that
incorporates untrusted input into an HTTP response server, tricking the server into terminating
the header section of the response early. By injecting a \r\n\r\n combination into the HTTP
header, they can insert their content into the body of the response.

However, the server application does not set headers based on untrusted client input, so this
exploit will not be possible.

##### Regex Injection Vulnerabilities

There are no concerns of regex injection in the application. The following regex statements were
found

```
/time=([\d.]+) ms/g)
```
This regex statement is built up statically so users are not able to influence the pattern. Also, the
values tested against are the output of a command. And lastly, the pattern is not sufficiently
complex enough to cause an issue. A free regex DOS checker shows this.


![image](https://github.com/user-attachments/assets/46681dc6-db4a-4429-889c-7de7ff95616c)


References:

https://devina.io/redos-checker

### no SQL injection

This project does not use any NoSQL databases so there are no vulnerabilities to exploit.

### LDAP injection

This project is not utilizing any LDAP service(s) so there are no vulnerabilities to exploit.





