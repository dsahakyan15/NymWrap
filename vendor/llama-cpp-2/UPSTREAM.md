# NymWrap file-handle bridge

Base: llama-cpp-2 0.1.161, upstream utilityai/llama-cpp-rs commit
e7af607ebd5ec2932709ef918c17cca2f9b0fce4, subdirectory llama-cpp-2.
Published crate SHA-256:
7e5249e590eab4a5015ba35cf078a4548b941e841ef8024310c3a10b2edb7179.
Archive was verified before copying; MIT/Apache licenses are from that commit.

Patch: Windows-only safe load_from_open_file, tiny owned CRT bridge in model/sys,
build.rs and pinned existing cc 1.11.3. The pinned llama.cpp already exports
llama_model_load_from_file_ptr. No native parser, sampler or cryptography is changed.
File handles are duplicated, mmap is disabled, and the FILE* is closed after
synchronous loading. The LlamaModel representation and normal pathname API remain.
Feature gates on common/mtmd-only helpers and imports also avoid unused-code
warnings in the CPU-only configuration; their enabled-feature behavior is unchanged.
