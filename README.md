## What is Threat Hunting?

**Threat Hunting** is a proactive approach to cybersecurity where analysts actively search for hidden threats in IT environments before those threats trigger alarms or cause obvious damage.
Instead of waiting for automated alerts, a threat hunter formulates hypotheses about potential malicious behaviour and then investigates system logs, network traffic, and other data to find signs of compromise.
In short, threat hunting helps defenders uncover sneaky attacks or anomalies that slip past traditional security tools, strengthening an organisation’s ability to detect and respond to incidents

### About This Repository
The purpose of this repository is to provide a guided, practical introduction to threat hunting through a series of real-world-inspired labs.
Whether you're a student just starting in cybersecurity or an experienced security practitioner, these labs will help you practice analysing security data and detecting malicious activity in controlled scenarios.
Each lab focuses on a common threat scenario and teaches techniques to uncover evidence of attacks or unauthorised behaviour.

By working through these exercises, you'll sharpen your skills in examining logs, investigating system changes, and spotting suspicious patterns—capabilities highly valued on security teams and sought after by recruiters.
The tone of the materials is beginner-friendly (each lab comes with step-by-step guidance), but you'll also find plenty of technical detail and terminology to mirror what real threat hunters do in the field.
This makes the repository welcoming to newcomers while still appealing to seasoned professionals who want to see practical examples of threat hunting in action.

## Labs Overview

### [Threat Hunting Scenario (Tor Browser)](https://github.com/itsrubenclarke/Threat-Hunting/blob/main/Windows-Threats/Tor-Browser/README.md) 
Explore how to detect and investigate the use of the Tor Browser on a system or network.
This lab centres on identifying suspicious browser artefacts and network connections related to Tor (The Onion Router), an anonymity network often used to mask browsing activity.
You’ll learn how threat actors might leverage Tor to evade detection and how to recognise those tell-tale signs in your environment.

### [Threat Hunting Scenario (System Configuration)](https://github.com/itsrubenclarke/Threat-Hunting/blob/main/Windows-Threats/System-Configuration/README.md)
Learn to spot and analyse unauthorised changes to system configuration.
This lab focuses on catching Windows Registry edits and other system tweaks that attackers might use to escalate privileges or disable security controls.
By investigating these changes, you'll understand how to detect attempts to bypass system hardening measures and compromise a machine from within.

### [Threat Hunting Scenario (Impossible Travel)](https://github.com/itsrubenclarke/Threat-Hunting/blob/main/Windows-Threats/Impossible-Travel/README.md)
Practice identifying potential account compromise by analysing login records for "impossible travel" patterns.
In this scenario, you'll sift through authentication logs to find when a user account is accessed from geographically distant locations in a short time frame—something a legitimate user couldn’t physically do.
This lab demonstrates how to detect suspicious login behaviour and helps you build alerts for unauthorised access based on location anomalies.

