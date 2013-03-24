#!/usr/binenv python

import itertools
import sys

# Method   seq  r  result                   Num results
# product  ABCD 2  AA AB AC AD BA BB BC BD  n**r        4**2          16
#                  CA CB CC CD DA DB DC DD    
# perm'ns  ABCD 2  AB AC AD BA BC BD CA CB  n!/(n-r)!   4*3*2/2       12
#                  CD DA DB DC
# comb'ns  ABCD 2  AB AC AD BC BD CD        n!/r!(n-r)! 4*3*2/2*2      6
# c'w'repl ABCD 2  AA AB AC AD BB BC BD CC  (n+r-1)!/r!(n-1)!
#                  CD DD                                5*4*3*2/2*3*2 10

EXPANDERS = {
    'product': lambda it, r: itertools.product(it, repeat=r),
    'permutations': itertools.permutations,
    'combinations': itertools.combinations,
    'combinations-replace': itertools.combinations_with_replacement,
    }

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('wordlist', type=open, default=sys.stdin)
    parser.add_argument('--expander', default='product',
                        choices=EXPANDERS)
    parser.add_argument('-r', '--repeat', type=int, default=3)
    parser.add_argument('--min-length', type=int)
    parser.add_argument('--max-length', type=int)
    args = parser.parse_args()

    words = (line.rstrip('\r\n') for line in args.wordlist)
    expander_fn = EXPANDERS[args.expander]
    words = expander_fn(words, args.repeat)

    if args.min_length is not None and args.max_length is not None:
        words = (t for t in words
                 if args.min_length <= sum(map(len, t)) <= args.max_length)
    elif args.min_length is not None:
        words = (t for t in words
                 if args.min_length <= sum(map(len, t)))
    elif args.max_length is not None:
        words = (t for t in words
                 if sum(map(len, t)) <= args.max_length)

    for t in words:
        for w in t:
            sys.stdout.write(w)
        sys.stdout.write('\n')

if __name__ =='__main__':
    main()
