import clang.cindex

# Set the library file explicitly if needed
clang.cindex.Config.set_library_file(r'C:\Program Files\LLVM\bin\libclang.dll')  # Update with your path
index = clang.cindex.Index.create()
print("Clang Index created successfully!")
