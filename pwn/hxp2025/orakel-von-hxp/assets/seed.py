from z3 import *

def solve_for_seed(target_output):
    # Standard MT19937 parameters
    N = 624
    M = 397
    
    # 1. Setup the Solver
    s = Solver()
    seed = BitVec('seed', 32)

    # 2. Replicate Seeding Logic (LCG)
    # mt[0] = seed
    # mt[i] = (6069 * mt[i-1]) % 2^32
    mt0_old = seed
    mt1_old = (6069 * mt0_old)
    
    # We need mt[397] for the first twist.
    # mt[397] = seed * (6069^397) mod 2^32
    multiplier_397 = pow(6069, 397, 2**32)
    mt397_old = (multiplier_397 * mt0_old)

    # 3. Replicate the First Twist
    # y = (mt[0] & UPPER) | (mt[1] & LOWER)
    upper_mask = 0x80000000
    lower_mask = 0x7fffffff
    mag1 = 0x9908b0df
    
    y_twist = (mt0_old & upper_mask) | (mt1_old & lower_mask)
    
    # We use LShR (Logical Shift Right) to match C's unsigned shift.
    # We use BitVecVal to ensure the types (Sorts) match for the XOR operation.
    twist_val = LShR(y_twist, 1) ^ If((y_twist & 1) == 1, 
                                     BitVecVal(mag1, 32), 
                                     BitVecVal(0, 32))
    
    # mt[0]_new = mt[397]_old ^ twist_val
    mt0_new = mt397_old ^ twist_val

    # 4. Replicate Tempering
    y = mt0_new
    y ^= LShR(y, 11)
    y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000
    y ^= LShR(y, 18)

    # 5. Add Constraint and Solve
    s.add(y == BitVecVal(target_output, 32))
    
    print(f"[*] Searching for seed that produces {hex(target_output)}...")
    if s.check() == sat:
        model = s.model()
        res = model[seed].as_long()
        print(f"[*] Success!")
        print(f"[*] Seed (Decimal): {res}")
        print(f"[*] Seed (Hex):     {hex(res)}")
        return res
    else:
        print("[!] No seed found. Check if the output index or constants are correct.")
        return None

if __name__ == "__main__":
    # Your target output
    target = 0x4000D000
    solve_for_seed(target)