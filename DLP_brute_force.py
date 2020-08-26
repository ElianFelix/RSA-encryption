
def dl_search(a, b, p):
    for x in range(2, p-2):
        if (a**x)%p == b:
            return x
    return -1


print('x = ', dl_search(106, 12375, 24691))
