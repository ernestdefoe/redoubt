# Reporting a security problem

Redoubt runs a service as `LocalSystem`, loads a DLL into every PowerShell,
Office and .NET process on the machine, and opens a named pipe that anything
at any integrity level can connect to. That is a lot of surface, and it is
there on purpose — but it means a bug here can be somebody else's foothold.

**Please report privately first.** Email `ernestdefoe@gmail.com` with
`Redoubt security` in the subject. Please don't open a public issue for
anything exploitable until there is a fix available.

I'll acknowledge within a few days. This is a personal project, not a company
with an on-call rota, so please read that as a genuine best effort rather than
a service commitment.

## What is worth reporting

The things most likely to matter, roughly in order:

- **Anything that gets code running as `LocalSystem`** through the service,
  the scan pipe, or the update path.
- **Anything a non-administrator can do to the scan pipe** that affects other
  users on the machine. The pipe has a null DACL by design — AMSI hosts run at
  every integrity level and a pipe they cannot open never gets asked — so the
  protocol is deliberately tiny. If you can make it do more than return a
  verdict, that is a bug.
- **A crash or hang in the AMSI provider.** It runs inside somebody else's
  process, on their thread. It is wrapped in `catch_unwind` and bounded by a
  two-second deadline; if you can get past either, that is a bug.
- **Anything that makes Redoubt destroy data it should not** — a quarantine
  path that escapes its directory, a restore that overwrites the wrong file.
- **Anything that makes Redoubt cut a machine off the network permanently.**
  The WFP session is dynamic precisely so this cannot happen; if you find a
  path where filters outlive the process, that is a bug.

## What is already known and is not a vulnerability

Stated so you don't spend time on them:

- **The installer and binaries are not code-signed.** SmartScreen warns. This
  is a cost problem, not an oversight.
- **There is no pre-execution blocking for executable files.** That needs a
  filesystem minifilter, which needs a Microsoft-signed kernel driver. A
  malicious executable is caught when it is written, not when it is launched.
- **Network blocking cannot observe, only block.** Watching connections needs
  a callout driver.
- **Redoubt fails open.** If the service is down, scripts run. That is
  deliberate: a tool that blocks everything when its own service dies breaks
  the machine and gets itself uninstalled.
- **Most ClamAV logical signatures are not evaluated** — the interface says how
  many. Reduced coverage, honestly reported, is not a vulnerability.

## False positives

Not a security issue, but I want to hear about them: a false positive in
enforce mode can cost somebody a file. Open a normal issue with the detection
name and, if you can, the file. `%ProgramData%\Redoubt\quarantine` holds
anything that was taken, and it can be restored byte-for-byte.
