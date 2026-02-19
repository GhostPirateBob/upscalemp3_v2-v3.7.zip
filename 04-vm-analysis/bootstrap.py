# Bootstrap to write analyze_vm.py without shell escaping issues
import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))
print(os.getcwd())
# The actual script will be written by appending
