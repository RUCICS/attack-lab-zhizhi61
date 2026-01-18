
with open('ans4.txt', 'wb') as f:
    f.write(b'zhizhi61\n')
    f.write(b'yeah...\xe3\x80\x82\n') # yeah...。 (UTF-8 encoding for 。)
    f.write(b'-1\n')

print("Created ans4.txt")
