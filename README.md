# ExpBridge

## What is ExpBridge

ExpBridge is a research project that aims to adapt Linux upstream PoCs to downstream distributions.
It provides rich interfaces that let you do a lot of cool things with Syzbot bugs

- Bug Reproduce (Upstream/Downstream)
- VM Management
- Kernel Tracing
- Integration with other Syzbot-based tools [[SyzScope](https://github.com/plummm/SyzScope)]

## Why did we develop ExpBridge

Exploitability assessment is a popular topic in cybersecurity. Most exploitability assessment tools primarily focus on Linux upstream kernel, which means they rely on original upstream PoCs. However, only a small portion (19%) of those upstream PoCs can trigger the same bugs on downstream distros. ExpBridge provides a capability to bridge this gap between upstream and downstream, adapting the upstream PoCs to downstream, providing more possibility to exploitability assessment tools.

## How to use

### Build your own plugin
It's super easy to integrate other bug assessment tools or build your own plugin on ExpBridge.

Here is a tutorial for building a bug-bisection plugin: [BugBisection]()

## Quick Start
- [Install Instructions](https://github.com/plummm/ExpBridge/wiki)
- [Documentation](https://github.com/plummm/ExpBridge/wiki)
- [API reference](https://github.com/plummm/ExpBridge/wiki/API-Reference)
- [Example Plugins](https://github.com/plummm/ExpBridge/wiki/Plugins)
