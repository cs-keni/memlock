CS 433 Project Proposal
C Vulnerability Assessment Program
James Smith, Saint George Aufranc, Kenny Nguyen

1. Problem Statement
Problem
Software products often have vulnerabilities in the source code, which mainly come from bad habits in programming or unawareness (i.e. memory handling leading to a leakage, improperly programmed critical sections of code, hardcoded values, ports left open, buffer overflows). Analyzing the code manually and identifying these issues through code review is time-consuming and prone to human error.
Why is this problem interesting? 
Vulnerabilities can be exploited by malicious parties, and being able to eliminate them at the source code level reduces the threats associated with a program
Developers who are less familiar with computer security may not know what to look for
Even experienced developers might forget to check for certain things in their code

2. Status Quo
Current solutions
Linters and security scanners scan for very basic risks and don’t cover all possible risks
Compiler warnings
Manual code review (can be done by multiple developers for redundancy, which takes time)
What’s inadequate
Some tools give false positive results
Tools can only cover a limited amount of vulnerabilities

3. Requirements and Challenges
Requirements
Accurate detection of known vulnerability patterns
Low false-positive rate
Scalability to multi-file projects
Efficient logging messages for developers (for easier debugging)
Challenges
Parsing real-world code
Not giving false positives and/or missing vulnerabilities which we intend to identify
We will not always know the intended uses and inputs for a program
Scope - we cannot hope to detect all vulnerabilities; project scope may have to be limited to specific vulnerability types or enforcing certain defined standards

4. Project Plan
Conceptualize project and constraints
Identify security vulnerabilities which we hope to address
Coding 
Create testing code - vulnerable source code files to be scanned
Testing, evaluation, documentation, delivery
Roles (Ambiguous for now, subject to change. All members responsible for coding program logic)
James: Parsing & communication
Kenny: Vulnerability rule design
Saint George: Evaluation/testing, metrics

5. Deliverables
Code (scanner and rules), a report, slides, and possibly a demo video scanning file(s)/directory

6. References

https://xiongyingfei.github.io/papers/icse15a.pdf

https://owasp.org/Top10/2025/

https://www.code-intelligence.com/blog/most-dangerous-vulnerabilities-cwes-in-c-2025

https://www.tandfonline.com/doi/full/10.1080/01972243.2025.2475311

https://ceur-ws.org/Vol-3598/paper13.pdf

https://www.sciencedirect.com/science/article/pii/S1877050917322755
