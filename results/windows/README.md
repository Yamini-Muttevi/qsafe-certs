Windows benchmark runs (Intel Core i9-13900H, liboqs 0.15.0 built with Visual Studio 2022).

results_windows_20261104_1045.md is an earlier uncontrolled run, about 1.5-2x slower for every algorithm, and is excluded from the paper. The 20261106 runs are the controlled runs reported in the paper. results_windows.txt is console output from the original benchmark script.

Note: rows labelled SLH-DSA in these runs were measured with SPHINCS+-SHA2-128s-simple, because real SLH-DSA fails its self-test in this build. Fixed in v0.2.
