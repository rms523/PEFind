# PEFind
This tool was created to assist in static detection writing based on strings. Couldn't find any existing tool which is simple enough and allows to search various string formats in multiple files and sort the results.

Search for ascii, unicode strings in PE files and sort the result.
![image](https://user-images.githubusercontent.com/19687913/184080841-8219a05b-079f-41fd-9db3-48c571410cf7.png)

Search for unicode string "Setup" in given folder E:\tmp
![image](https://user-images.githubusercontent.com/19687913/184079627-e5243f63-cc54-44c1-a52d-327e26bbd61f.png)

Sort the results by filepath ( -s 0 ) , fileOffset ( -s 1 ) , section index ( -s 2 ) and so on.

![image](https://user-images.githubusercontent.com/19687913/184079778-7b9db953-791a-488c-b363-35cf9443a368.png)

Search for both ascii and unicode strings in give folder and sort the result by section name.
![image](https://user-images.githubusercontent.com/19687913/184081676-676310a2-d7e7-44c6-b6c2-475fcacbf1f2.png)

If PE is invalid or string is not present in PE sections ( i.e string in overlay or in PE header ) , it will show Invalid PE or string not in sections.

