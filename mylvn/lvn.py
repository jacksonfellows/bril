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
            if block:
                blocks.append(block)
            block = [instr]
        else:
            pass
    if block:
        blocks.append(block)
    return blocks

def lookup(tup, table):
    if tup[0] == 'id':
        return tup[1]
    for i,row in enumerate(table):
        if tup == row[1]:
            return i
    raise KeyError

def instr2tup(instr, env):
    if instr['op'] == 'const':
        return ('const', instr['value'])
    if instr['op'] in {'add', 'mul'}:
        return tuple([instr['op']] + sorted([env[arg] for arg in instr['args']]))
    return tuple([instr['op']] + [env[arg] for arg in instr['args']] if 'args' in instr else [])

def tup2instr(instr, tup, table, env):
    if 'dest' in instr and table[env[instr['dest']]][3] is not None:
        return {'dest': instr['dest'], 'type': instr['type'], 'op': 'const', 'value': table[env[instr['dest']]][3]}
    new_instr = {}
    for prop in {'dest', 'op', 'type', 'value'}:
        if prop in instr:
            new_instr[prop] = instr[prop]
    if 'args' in instr:
        new_instr['args'] = [table[env[arg]][2] for arg in instr['args']]
    return new_instr

from operator import add, mul

folders = {
    'add': add,
    'mul': mul,
}

def make_constant(tup, table):
    if tup[0] == 'const':
        return tup[1]
    if tup[0] in folders and all(table[i][3] is not None for i in tup[1:]):
        return folders[tup[0]](*(table[i][3] for i in tup[1:]))

def lvn(block):
    new_block = []
    table = []
    env = {}
    for instr in block:
        if 'op' not in instr:
            new_block.append(dict(instr))
            continue
        if 'args' in instr:
            for unknown in (arg for arg in instr['args'] if arg not in env):
                i = len(table)
                table.append((i, None, unknown, None))
                env[unknown] = i
        tup = instr2tup(instr, env)
        if 'dest' in instr:
            try:
                env[instr['dest']] = lookup(tup, table)
            except KeyError:
                i = len(table)
                table.append((i, tup, instr['dest'], make_constant(tup, table)))
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
