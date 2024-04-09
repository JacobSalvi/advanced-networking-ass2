#!/usr/bin/python3

import sys

network_filename = sys.argv[1]
flow_source = int(sys.argv[2])
flow_target = int(sys.argv[3])

# we represent the network graph G=(V,E) with an array V representing
# the vertices indexed starting from position 1, and an array E of
# edge descriptors consisting of a triple (u, v, r), where u and v are
# integer vertex identifiers, with u<v, and r is a float representing
# the link capacity.  V[u] is an array of the identifiers (positions
# in E) of the edges that are adjacent to node u.

V = []
E = []

f = open(network_filename, "r")
for l in f:
    edge = l.split()
    assert len(edge) >= 2
    u = int(edge[0])
    v = int(edge[1])
    if len(edge) > 2:
        r = float(edge[2])
    else:
        r = 1.0
    if u > v:
        u,v = v,u
    e_idx = len(E)
    E.append((u,v,r))
    for v_idx in [u,v]:
        if len(V) <= v_idx:
            V.extend([None]*(v_idx - len(V) + 1))
        if V[v_idx] == None:
            V[v_idx] = [e_idx]
        else:
            V[v_idx].append(e_idx)

f.close()

n = len(V) - 1                  # number of nodes
m = len(E)                      # number of edges

# We create a linear program in which we maximize the given flow
# The program has:
#
#   * n rows/contraints, each representing the flow-balance equation
#     for a vertex/router in the graph
#
#   * m+1 columns/variables, m of which are the portion of the flow
#     for each edge in the graph, and 1 is the total flow (lambda).
#
print('p', 'lp', 'max', n, m + 1, 2*m + 2)

# The name of the objective function
print('n z obj')

# Each column/variable corresponds to an edge-flow, is named x_1_2 for
# an edge (1,2), and is bounded by the capacity of that edge
for j in range(m):
    u, v, r = E[j]
    print('j', j+1, 'd', -r, r)
    print('n j', j+1, 'x_%d_%d' % (u,v))

# The last column/variable corresponds to the total flow, lambda,
# which is positive, meaning with lower-bound of 0
print('j', m + 1, 'l', 0)
print('n j', m + 1, 'lambda')

# Each row/constraint corresponds to the flow-balance equation for a
# vertex. Therefore, it's an equality constraint ('s') with value 0.
i = 1
for v in range(1, len(V)):
    print('i', i, 's', 0)
    print('n', 'i', i, 'v_%d' % v)
    i += 1

# The objective function is lambda, so the only non-zero coefficient
# on the zero row (the objective function) is a_{0,m+1}=1
print('a', 0, m + 1, 1)

# The other non-zero coefficients for the contraints matrix are the
# edges.  Thus a_i,j corresponds to the contribution of the j-th
# edge-flow variable to the i-th vertex flow-balance equation.  In
# particular, a_i,j is 1 if the edge-flow variable indicates an
# incoming flow from vertex i, or -1 if that flow is outgoing.
i = 1
for v in range(1,len(V)):
    for e in V[v]:
        u = E[e][0]
        if u < v:
            print('a', i, e+1, 1)
        else:
            print('a', i, e+1, -1)
    if v == flow_source:
        # if v is the source, we also add the total flow value (lambda)
        print('a', i, m + 1, 1)
    elif v == flow_target:
        # if v is the target, we also subtract the total flow value (lambda)
        print('a', i, m + 1, -1)
    i += 1

print('e')
