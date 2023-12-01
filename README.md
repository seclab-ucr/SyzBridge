# SyzBridge

## What is SyzBridge

SyzBridge is a research project that adapts Linux upstream PoCs to downstream distributions.
It provides rich interfaces that allow you to do a lot of cool things with Syzbot bugs

- Bug Reproduce (Upstream/Downstream)
- VM Management
- Kernel Tracing
- Integration with other Syzbot-based tools [SyzScope](https://github.com/plummm/SyzScope)

Access to our [paper](./SyzBridge-Camera_Ready.pdf) for more details
```
@inproceedings{syzbridge,
  author    = {Xiaochen Zou and Yu Hao and Zheng Zhang and Juefei Pu and Weiteng Chen and Zhiyun Qian},
  title     = {{SyzBridge: Bridging the Gap in Exploitability Assessment of Linux Kernel Bugs in the Linux Ecosystem}},
  booktitle = {31st Annual Network and Distributed System Security Symposium, {NDSS}},
  year      = {2024},
}
```

## Why did we develop SyzBridge

Exploitability assessment is a popular topic in cybersecurity. Most exploitability assessment tools primarily focus on Linux upstream kernel, which means they rely on original upstream PoCs. However, only a small portion (19%) of those upstream PoCs can trigger the same bugs on downstream distros. SyzBridge provides a capability to bridge this gap between upstream and downstream, adapting the upstream PoCs to downstream, providing more possibility to exploitability assessment tools.

## How to use

### Build your own plugin
It's super easy to integrate other bug assessment tools or build your own plugin on SyzBridge.

Here is a tutorial for building a bug-bisection plugin: [BugBisection](../../wiki/Plugins#write-your-own-plugin)

## Request module fuzzing
We used a customized syzkaller to fuzz `request_mod` repo links [here](https://github.com/plummm/syzkaller-capability_inference/tree/module_fuzzing)

## Quick Start
- [Install Instructions](../../wiki)
- [Documentation](../../wiki)
- [API reference](../../wiki/API-Reference)
- [Example Plugins](../../wiki/Plugins)
