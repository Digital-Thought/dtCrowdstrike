def count(lst):
    cnt = 0
    if isinstance(lst, list):
        for entry in lst:
            cnt += 1
    else:
        for entry in lst():
            cnt += 1

    return cnt
