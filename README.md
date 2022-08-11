# PEFind
This tool was created to assist in static detection writing based on strings. Couldn't find any existing tool which is simple enough and allows to search various string formats in multiple files and sort the results.

Search for ascii, unicode strings in PE files and sort the result.
```
PEFind.exe
```
![image](https://user-images.githubusercontent.com/19687913/184084245-4186f63a-9f84-411e-a47b-cf7743b93506.png)

Search for unicode string "Setup" in given folder E:\tmp
```
PEFindC1.exe -u E:\tmp "Setup"
```
![image](https://user-images.githubusercontent.com/19687913/184084967-5b05911c-cb51-4af7-9255-06e73498ce26.png)

Sort the results by filepath ( -s 0 ) , fileOffset ( -s 1 ) , section index ( -s 2 ) and so on.
```
PEFindC1.exe -u -s 1 E:\tmp "Setup"
```
![image](https://user-images.githubusercontent.com/19687913/184094814-542d1f98-fc14-4934-bc96-5ba37941cdd9.png)

Search for both ascii and unicode strings in give folder and sort the result by section index.
```
PEFindC1.exe -au -s 2 E:\tmp "Setup"
```
![image](https://user-images.githubusercontent.com/19687913/184095029-a08f6562-3417-40d5-91aa-ffb9758eefa0.png)

If PE is invalid or string is not present in PE sections ( i.e string in overlay or in PE header ) , it will show Invalid PE or string not in sections.

