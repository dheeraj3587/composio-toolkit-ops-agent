---
inclusion: always
---
# Execution discipline

Work in vertical slices that close a real user-visible or system-visible gap. Read current code and tests before proposing changes. Reuse existing abstractions.

For each task:
1. describe current behavior;
2. state acceptance criteria;
3. add or update tests;
4. implement the smallest coherent change;
5. run focused tests;
6. run the affected full gate;
7. inspect the diff;
8. update docs only for real behavior changes;
9. report live versus fixture evidence.

Do not push, deploy, send email, launch paid browser sessions, or perform live provider actions without explicit authorization.
