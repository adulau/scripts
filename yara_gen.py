#!/usr/bin/python
#
# Generate Yara rules from a list of strings

import yara_tools
import yara
import argparse
import os
import fileinput
import sys

usage = "usage: %prog [options]"

parser = argparse.ArgumentParser(
    description="Generate Yara rules from a list of strings", epilog=""
)

parser.add_argument(
    "-n",
    dest="name",
    help="set name of the Yara rule",
    type=str,
    default="default_rule_name",
)
default_author = os.getlogin()
parser.add_argument(
    "-a",
    dest="author",
    help="set name of the Yara rule author",
    type=str,
    default=default_author,
)
parser.add_argument(
    "-p",
    dest="purpose",
    help="set the purpose of the Yara rule",
    type=str,
    default="Purpose not set",
)

options = parser.parse_args()

rule = yara_tools.create_rule(name=f'{options.name}', default_boolean='or')
rule.add_meta(key="author", value=f'{options.author}')
rule.add_meta(key="purpose", value=f'{options.purpose}')

s = []
for line in fileinput.input('-'):
    l = line.rstrip()
    if l:
        s.append(l)
rule.add_strings(
    strings=s, modifiers=['wide', 'ascii'], condition="any of ($IDENTIFIER*)"
)

generated_rule = rule.build_rule()

print(generated_rule)
