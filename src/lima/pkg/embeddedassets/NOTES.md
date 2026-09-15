# Single-file Lima assets

The guest agent (lima-guestagent.Linux-x86_64) and examples are copied unchanged
from the original Lima 0.13 bundle's share/lima directory. The guest agent is a
Linux x86_64 executable; other guest architectures are not included. The examples
retain upstream architecture alternatives, but this build accepts only x86_64.

The adjacent LICENSE is Lima's Apache License 2.0. examples/README.md preserves
upstream template notes. These files are embedded as well as the runtime assets.
Go module dependencies retain their respective licenses. Native QEMU, firmware,
and native dependency license/source notices must accompany the final distribution;
this Lima license is not a substitute for their licenses or source obligations.

Assets are read in memory: the guest agent is streamed into cidata.iso and YAML
is read from an embedded filesystem. No share/lima directory or temporary asset
extraction is used. VM disks, cidata.iso, downloads and editor work files remain
normal persistent/working storage, not extracted runtime assets.
