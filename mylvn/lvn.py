#!/usr/bin/env python3
def basic_blocks(instrs):
    blocks = []
    block = []
    for instr in instrs:
        if 'op' in instr:
            block.append(instr)
            if instr['op'] in {'jmp', 'br', 'ret'}:
                blocks.append(block)
                block = []
        elif 'label' in instr:
            blocks.append(block)
            block = [instr]
        else:
            pass
    blocks.append(block)
    return blocks

def lookup(tup, table):
    for i,row in enumerate(table):
        if tup == row[1]:
            return i
    raise KeyError

def instr2tup(instr, env):
    if instr['op'] == 'const':
        return ('const', instr['value'])
    return tuple([instr['op']] + [env[arg] for arg in instr['args']])

def tup2instr(instr, tup, table, env):
    new_instr = {}
    for prop in ['dest', 'op', 'type', 'value']:
        if prop in instr:
            new_instr[prop] = instr[prop]
    if 'args' in instr:
        new_instr['args'] = [table[env[arg]][2] for arg in instr['args']]
    return new_instr

def lvn(block):
    new_block = []
    table = []
    env = {}
    for instr in block:
        tup = instr2tup(instr, env)
        if 'dest' in instr:
            try:
                env[instr['dest']] = lookup(tup, table)
            except KeyError:
                i = len(table)
                table.append((i, tup, instr['dest']))
                env[instr['dest']] = i
        new_block.append(tup2instr(instr, tup, table, env))
    return new_block

def optimize(prog):
    new_prog = {'functions': []}
    for func in prog['functions']:
        new_func = {'name': func['name'], 'instrs': []}
        for block in basic_blocks(func['instrs']):
            new_func['instrs'] += lvn(block)
        new_prog['functions'].append(new_func)
    return new_prog

import json, sys
json.dump(optimize(json.load(sys.stdin)), sys.stdout, indent=2, sort_keys=True)
print()
