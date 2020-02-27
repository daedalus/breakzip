M = 2^32
c = 0x08088405
L = matrix([
    [  M,  0,  0,  0],
    [c^1, -1,  0,  0],
    [c^2,  0, -1,  0],
    [c^3,  0,  0, -1]
])
B = L.LLL()
size = 4

k10 = randint(0, M)
ks = [ c^(n + 1) * k10 % M for n in range(size) ]
print "ks: "
print map(hex, ks)
msbs = [(k & 0xff0c0000) for k in ks]
secret = [ks[i] - msbs[i] for i in range(size)]
w1 = B * vector(msbs)
w2 = vector([ round(RR(w) / M) * M - w for w in w1 ])
guess = list(B.solve_right(w2))
print "guess: "
# print [hex(Integer(guess[i])) for i in range(size)]
print guess

print "diff from msb + guess: "
# print [hex(Integer(ks[i] - msbs[i] - guess[i])) for i in range(size)]
print vector(ks) - vector(msbs) - vector(guess)
