bad1 = r'(a*)*'
bad2 = r'((a+|b)c?)+'
bad3 = r'(x+x+)+y'
bad4 = r'(.|[abc])+z'

fine1 = r'xx+y'  # Fixed bad3
fine2 = r'.+z'  # Fixed bad4
