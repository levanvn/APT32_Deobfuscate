1.Run Deobfuscate.py, apply patches to file (Edit -> Patch Program -> apply patches to input file...), and reload file
2.Run Deobfuscate_2.py,  apply patches to file, and reload file 
3.Ready to using Hex-ray Decompiler
Note:
-Need to reload the file because IDA needs to recalculate the stack poiter
-IDA cannot recognize some basic-blocks (IDA cannot creates function), so we need to be manipulated manually by keypatch (https://www.keystone-engine.org/keypatch/)