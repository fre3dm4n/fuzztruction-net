#!/bin/bash
export FT_CUSTOM_PATCH_POINTS=1
/home/user/fuzztruction/generator/pass/fuzztruction-source-clang-fast -g -O3 -DFT_GENERATOR -I/home/user/fuzztruction/generator/pass generator.c -o generator
